#include "vpack/anti_dump.h"
#include "vpack/page_vault.h"
#include "vpack/crypto.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <intrin.h>
#include <cstring>
#include <atomic>

namespace vpack::antidump {

namespace {

struct UnicodeStringT {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
};

struct PebLdrDataT {
    ULONG      Length;
    BOOLEAN    Initialized;
    PVOID      SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
};

struct LdrDataTableEntryLoadOrderT {
    LIST_ENTRY     InLoadOrderLinks;
    LIST_ENTRY     InMemoryOrderLinks;
    LIST_ENTRY     InInitializationOrderLinks;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UnicodeStringT FullDllName;
    UnicodeStringT BaseDllName;
};

VPACK_FORCEINLINE uint8_t* get_peb_mutable() noexcept {
#if defined(_M_X64) || defined(__x86_64__)
    return reinterpret_cast<uint8_t*>(__readgsqword(0x60));
#elif defined(_M_IX86) || defined(__i386__)
    return reinterpret_cast<uint8_t*>(__readfsdword(0x30));
#else
    return nullptr;
#endif
}

VPACK_FORCEINLINE uint64_t rotr64(uint64_t x, int n) noexcept {
    return (x >> n) | (x << (64 - n));
}

// Reads Kernel InterruptTime from KUSER_SHARED_DATA (0x7FFE0008)
VPACK_FORCEINLINE uint64_t read_kuser_interrupt_time() noexcept {
    const volatile uint64_t* kuser_time = reinterpret_cast<const volatile uint64_t*>(0x7FFE0008ULL);
    return *kuser_time;
}

uint64_t hash_unicode_ci(const wchar_t* buf, size_t char_len) noexcept {
    uint64_t hash = 0xCBF29CE484222325ULL;
    for (size_t i = 0; i < char_len; ++i) {
        wchar_t wc = buf[i];
        if (wc >= L'A' && wc <= L'Z') {
            wc = static_cast<wchar_t>(wc + (L'a' - L'A'));
        }
        hash ^= static_cast<uint8_t>(wc & 0xFF);
        hash *= 0x100000001B3ULL;
    }
    return hash;
}

ModuleLayoutInfo g_cached_main_layout{};
bool             g_has_cached_layout = false;

// ============================================================================
// JIT .vcode Vault State (Dynamically Masked in RAM — Zero Static Ptr Key)
// ============================================================================
uintptr_t             g_jit_ptr_mask       = 0;
uintptr_t             g_vcode_encoded_base = 0;
size_t                g_vcode_size         = 0;
uint64_t              g_vcode_plain_hash   = 0;
uint64_t              g_vcode_cipher_hash  = 0;
uint64_t              g_vcode_rolling_key  = 0;
std::atomic<uint64_t> g_vcode_generation{0};
std::atomic<bool>     g_vcode_jit_active{false};
std::atomic<bool>     g_vcode_tampered{false};

std::atomic<DWORD>    g_jit_owner_tid{0};
uint32_t              g_jit_recursion_depth = 0;

void acquire_jit_lock() noexcept {
    const DWORD self_tid = GetCurrentThreadId();
    if (g_jit_owner_tid.load(std::memory_order_acquire) == self_tid) {
        return;
    }
    DWORD expected = 0;
    while (!g_jit_owner_tid.compare_exchange_weak(
        expected, self_tid, std::memory_order_acquire, std::memory_order_relaxed)) {
        expected = 0;
        _mm_pause();
    }
}

void release_jit_lock() noexcept {
    g_jit_owner_tid.store(0, std::memory_order_release);
}

// Fast GF(2^64) + Non-Linear MBA stream cipher for in-memory JIT code pages
void jit_mba_stream_transform(uint8_t* buf, size_t size, uint64_t key) noexcept {
    uint64_t state = crypto::mba_xor(key, 0xC983E5A19F27B4D3ULL);
    size_t words = size / 8;
    auto* wptr = reinterpret_cast<uint64_t*>(buf);
    for (size_t i = 0; i < words; ++i) {
        state = crypto::mba_add(rotr64(state, 17), 0x9E3779B97F4A7C15ULL * (i + 1));
        uint64_t ks = crypto::poly_permute_64(state, key ^ static_cast<uint64_t>(i));
        wptr[i] ^= ks;
    }
    for (size_t i = words * 8; i < size; ++i) {
        state = crypto::mba_add(rotr64(state, 11), 0xBF58476D1CE4E5B9ULL);
        buf[i] ^= static_cast<uint8_t>((state ^ (state >> 29)) & 0xFFu);
    }
}

// Homomorphic Ciphertext-to-Ciphertext Re-Keying: transitions .vcode directly from
// Stream(old_key) to Stream(new_key) via XOR delta WITHOUT ever exposing plaintext in RAM!
void jit_mba_homomorphic_rekey(uint8_t* buf, size_t size, uint64_t old_key, uint64_t new_key) noexcept {
    uint64_t s_old = crypto::mba_xor(old_key, 0xC983E5A19F27B4D3ULL);
    uint64_t s_new = crypto::mba_xor(new_key, 0xC983E5A19F27B4D3ULL);
    size_t words = size / 8;
    auto* wptr = reinterpret_cast<uint64_t*>(buf);
    for (size_t i = 0; i < words; ++i) {
        s_old = crypto::mba_add(rotr64(s_old, 17), 0x9E3779B97F4A7C15ULL * (i + 1));
        s_new = crypto::mba_add(rotr64(s_new, 17), 0x9E3779B97F4A7C15ULL * (i + 1));
        uint64_t ks_old = crypto::poly_permute_64(s_old, old_key ^ static_cast<uint64_t>(i));
        uint64_t ks_new = crypto::poly_permute_64(s_new, new_key ^ static_cast<uint64_t>(i));
        wptr[i] ^= (ks_old ^ ks_new);
    }
    for (size_t i = words * 8; i < size; ++i) {
        s_old = crypto::mba_add(rotr64(s_old, 11), 0xBF58476D1CE4E5B9ULL);
        s_new = crypto::mba_add(rotr64(s_new, 11), 0xBF58476D1CE4E5B9ULL);
        uint8_t b_old = static_cast<uint8_t>((s_old ^ (s_old >> 29)) & 0xFFu);
        uint8_t b_new = static_cast<uint8_t>((s_new ^ (s_new >> 29)) & 0xFFu);
        buf[i] ^= static_cast<uint8_t>(b_old ^ b_new);
    }
}

bool protect_memory_via_syscall(void* base, size_t size, DWORD new_protect, DWORD* out_old_protect) noexcept {
    DWORD old_prot = 0;
    static SyscallEntry sc_protect{};
    static bool sc_resolved = false;
    if (!sc_resolved) {
        sc_resolved = resolve_ntdll_syscall(VPACK_HASH_CI("NtProtectVirtualMemory"), sc_protect);
    }

    if (sc_resolved && sc_protect.gadget_addr && sc_protect.ssn != 0xFFFFFFFFu) {
        PVOID  region_base = base;
        SIZE_T region_size = size;
        ULONG  old_p       = 0;
        long status = invoke_indirect_syscall(
            sc_protect,
             static_cast<uint64_t>(reinterpret_cast<uintptr_t>(GetCurrentProcess())),
            reinterpret_cast<uint64_t>(&region_base),
            reinterpret_cast<uint64_t>(&region_size),
            static_cast<uint64_t>(new_protect),
            reinterpret_cast<uint64_t>(&old_p)
        );
        if (status == 0) {
            if (out_old_protect) *out_old_protect = old_p;
            return true;
        }
    }

    using FnVirtualProtect = BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD);
    static auto fn_vp = VPACK_IMPORT(FnVirtualProtect, "kernel32.dll", "VirtualProtect");
    if (fn_vp.get() && fn_vp(base, size, new_protect, &old_prot)) {
        if (out_old_protect) *out_old_protect = old_prot;
        return true;
    }
    return false;
}

// Checks if an ntdll stub starts with `mov r10, rcx; mov eax, <ssn>` (4C 8B D1 B8)
VPACK_FORCEINLINE bool is_clean_syscall_prologue(const uint8_t* p) noexcept {
    return p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1 && p[3] == 0xB8 &&
           p[6] == 0x00 && p[7] == 0x00;
}

// Searches within a stub [p .. p+32) for `0F 05 C3` (syscall; ret)
const void* find_syscall_ret_gadget(const uint8_t* p) noexcept {
    for (size_t off = 0; off + 2 < 32; ++off) {
        if (p[off] == 0x0F && p[off + 1] == 0x05 && p[off + 2] == 0xC3) {
            return p + off;
        }
    }
    return nullptr;
}

struct ZwSyscallTableEntry {
    uint32_t       rva        = 0;
    uint64_t       nt_hash_ci = 0;
    uint64_t       zw_hash_ci = 0;
    const uint8_t* stub_ptr   = nullptr;
};

constexpr size_t    kMaxZwSyscalls  = 640;
ZwSyscallTableEntry g_zw_table[kMaxZwSyscalls]{};
size_t              g_zw_count      = 0;
bool                g_zw_table_init = false;

uint64_t hash_zw_as_nt_ci(const char* zw_name) noexcept {
    uint64_t hash = 0xCBF29CE484222325ULL;
    const char prefix[2] = {'n', 't'};
    for (char c : prefix) {
        hash ^= static_cast<uint8_t>(c);
        hash *= 0x100000001B3ULL;
    }
    const char* p = zw_name + 2;
    while (*p) {
        char c = *p++;
        if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c + ('a' - 'A'));
        }
        hash ^= static_cast<uint8_t>(c);
        hash *= 0x100000001B3ULL;
    }
    return hash;
}

void ensure_sorted_zw_table() noexcept {
    if (g_zw_table_init) return;

    uint8_t* peb = get_peb_mutable();
    if (!peb) return;
#if defined(_M_X64) || defined(__x86_64__)
    auto* ldr = *reinterpret_cast<PebLdrDataT**>(peb + 0x18);
#else
    auto* ldr = *reinterpret_cast<PebLdrDataT**>(peb + 0x0C);
#endif
    if (!ldr) return;

    LIST_ENTRY* head = &ldr->InLoadOrderModuleList;
    for (LIST_ENTRY* it = head->Flink; it && it != head; it = it->Flink) {
        auto* entry = reinterpret_cast<LdrDataTableEntryLoadOrderT*>(it);
        if (!entry->DllBase || !entry->BaseDllName.Buffer || entry->BaseDllName.Length == 0) {
            continue;
        }
        size_t char_count = entry->BaseDllName.Length / sizeof(wchar_t);
        if (hash_unicode_ci(entry->BaseDllName.Buffer, char_count) != VPACK_HASH_CI("ntdll.dll")) {
            continue;
        }

        const auto* mod_base = static_cast<const uint8_t*>(entry->DllBase);
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(mod_base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) break;
        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(mod_base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) break;

        const auto& exp_dir_entry = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (exp_dir_entry.VirtualAddress == 0 || exp_dir_entry.Size == 0) break;

        const auto* exp_dir = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(mod_base + exp_dir_entry.VirtualAddress);
        const auto* names   = reinterpret_cast<const DWORD*>(mod_base + exp_dir->AddressOfNames);
        const auto* funcs   = reinterpret_cast<const DWORD*>(mod_base + exp_dir->AddressOfFunctions);
        const auto* ords    = reinterpret_cast<const WORD*>(mod_base + exp_dir->AddressOfNameOrdinals);

        g_zw_count = 0;
        for (DWORD i = 0; i < exp_dir->NumberOfNames && g_zw_count < kMaxZwSyscalls; ++i) {
            const char* fn_name = reinterpret_cast<const char*>(mod_base + names[i]);
            if (fn_name[0] != 'Z' || fn_name[1] != 'w') continue;

            const DWORD func_rva = funcs[ords[i]];
            if (func_rva >= exp_dir_entry.VirtualAddress &&
                func_rva < exp_dir_entry.VirtualAddress + exp_dir_entry.Size) {
                continue; // Skip forwarded exports
            }

            ZwSyscallTableEntry item{};
            item.rva        = func_rva;
            item.nt_hash_ci = hash_zw_as_nt_ci(fn_name);
            item.zw_hash_ci = crypto::fnv1a_64_ci(fn_name);
            item.stub_ptr   = mod_base + func_rva;
            g_zw_table[g_zw_count++] = item;
        }

        // Insertion sort by ascending RVA: index in sorted Zw* table == Kernel SSN!
        for (size_t i = 1; i < g_zw_count; ++i) {
            ZwSyscallTableEntry key = g_zw_table[i];
            size_t j = i;
            while (j > 0 && g_zw_table[j - 1].rva > key.rva) {
                g_zw_table[j] = g_zw_table[j - 1];
                --j;
            }
            g_zw_table[j] = key;
        }

        g_zw_table_init = (g_zw_count > 0);
        break;
    }
}

} // namespace

bool resolve_ntdll_syscall(uint64_t proc_hash_ci, SyscallEntry& out_entry) noexcept {
    out_entry = SyscallEntry{};
    ensure_sorted_zw_table();

    for (size_t idx = 0; idx < g_zw_count; ++idx) {
        if (g_zw_table[idx].nt_hash_ci != proc_hash_ci &&
            g_zw_table[idx].zw_hash_ci != proc_hash_ci) {
            continue;
        }

        const uint8_t* fn_bytes = g_zw_table[idx].stub_ptr;
        if (is_clean_syscall_prologue(fn_bytes)) {
            out_entry.ssn         = *reinterpret_cast<const uint32_t*>(fn_bytes + 4);
            out_entry.gadget_addr = find_syscall_ret_gadget(fn_bytes);
            out_entry.is_hooked   = false;
        } else {
            // Function is inline-hooked (e.g. ScyllaHide JMP at +0x00 or +0x03).
            // Recover exact SSN from the sorted Zw* address table & nearest clean neighbor!
            out_entry.is_hooked = true;
            out_entry.ssn       = static_cast<uint32_t>(idx);

            for (size_t dist = 1; dist < g_zw_count; ++dist) {
                if (idx + dist < g_zw_count) {
                    const uint8_t* down = g_zw_table[idx + dist].stub_ptr;
                    if (is_clean_syscall_prologue(down)) {
                        const uint32_t neighbor_ssn = *reinterpret_cast<const uint32_t*>(down + 4);
                        if (neighbor_ssn >= static_cast<uint32_t>(dist)) {
                            out_entry.ssn = neighbor_ssn - static_cast<uint32_t>(dist);
                        }
                        out_entry.gadget_addr = find_syscall_ret_gadget(down);
                        if (out_entry.gadget_addr) break;
                    }
                }
                if (idx >= dist) {
                    const uint8_t* up = g_zw_table[idx - dist].stub_ptr;
                    if (is_clean_syscall_prologue(up)) {
                        const uint32_t neighbor_ssn = *reinterpret_cast<const uint32_t*>(up + 4);
                        out_entry.ssn         = neighbor_ssn + static_cast<uint32_t>(dist);
                        out_entry.gadget_addr = find_syscall_ret_gadget(up);
                        if (out_entry.gadget_addr) break;
                    }
                }
            }
        }

        if (!out_entry.gadget_addr) {
            for (size_t k = 0; k < g_zw_count; ++k) {
                if (const void* g = find_syscall_ret_gadget(g_zw_table[k].stub_ptr)) {
                    out_entry.gadget_addr = g;
                    break;
                }
            }
        }
        return out_entry.ssn != 0xFFFFFFFFu && out_entry.gadget_addr != nullptr;
    }

    return false;
}

#if defined(_MSC_VER) && defined(_M_X64)
#pragma section(".vpvlt", execute, read)
#pragma code_seg(".vpvlt")
__declspec(allocate(".vpvlt")) alignas(16) const uint8_t kMsvcSyscallTrampoline[16] = {
    0x4C, 0x8B, 0xD1,             // mov r10, rcx
    0x8B, 0x44, 0x24, 0x60,       // mov eax, dword ptr [rsp + 0x60] (12th param: ssn)
    0xFF, 0x64, 0x24, 0x68,       // jmp qword ptr [rsp + 0x68]      (13th param: gadget_addr in ntdll)
    0xC3, 0x90, 0x90, 0x90, 0x90
};
#pragma code_seg()
#endif

VPACK_NOINLINE long invoke_indirect_syscall(
    const SyscallEntry& entry,
    uint64_t arg1,
    uint64_t arg2,
    uint64_t arg3,
    uint64_t arg4,
    uint64_t arg5,
    uint64_t arg6,
    uint64_t arg7,
    uint64_t arg8,
    uint64_t arg9,
    uint64_t arg10,
    uint64_t arg11
) noexcept {
    if (!entry.gadget_addr || entry.ssn == 0xFFFFFFFFu) {
        return -1;
    }
#if (defined(__GNUC__) || defined(__clang__)) && (defined(__x86_64__) || defined(_M_X64))
    long status = -1;
    volatile uint64_t stack_args[7] = { arg5, arg6, arg7, arg8, arg9, arg10, arg11 };

    register uint64_t r10_reg __asm__("r10") = arg1;
    register uint64_t rcx_reg __asm__("rcx") = arg1;
    register uint64_t rdx_reg __asm__("rdx") = arg2;
    register uint64_t r8_reg  __asm__("r8")  = arg3;
    register uint64_t r9_reg  __asm__("r9")  = arg4;
    register uint32_t eax_reg __asm__("eax") = entry.ssn;
    register const volatile uint64_t* rsi_sa __asm__("rsi") = &stack_args[0];
    register const void* rdi_gad __asm__("rdi") = entry.gadget_addr;

    __asm__ volatile(
        "subq $0x68, %%rsp\n\t"
        "movq 0x00(%%rsi), %%r11\n\t"
        "movq %%r11, 0x20(%%rsp)\n\t"
        "movq 0x08(%%rsi), %%r11\n\t"
        "movq %%r11, 0x28(%%rsp)\n\t"
        "movq 0x10(%%rsi), %%r11\n\t"
        "movq %%r11, 0x30(%%rsp)\n\t"
        "movq 0x18(%%rsi), %%r11\n\t"
        "movq %%r11, 0x38(%%rsp)\n\t"
        "movq 0x20(%%rsi), %%r11\n\t"
        "movq %%r11, 0x40(%%rsp)\n\t"
        "movq 0x28(%%rsi), %%r11\n\t"
        "movq %%r11, 0x48(%%rsp)\n\t"
        "movq 0x30(%%rsi), %%r11\n\t"
        "movq %%r11, 0x50(%%rsp)\n\t"
        "callq *%%rdi\n\t"
        "addq $0x68, %%rsp\n\t"
        : "=a"(status), "+r"(rcx_reg), "+r"(rdx_reg), "+r"(r8_reg), "+r"(r9_reg), "+r"(r10_reg)
        : "0"(eax_reg), "r"(rdi_gad), "r"(rsi_sa)
        : "memory", "cc", "r11"
    );
    return status;
#elif defined(_MSC_VER) && defined(_M_X64)
    using FnMsvcSyscall = long(*)(
        uint64_t, uint64_t, uint64_t, uint64_t,
        uint64_t, uint64_t, uint64_t, uint64_t,
        uint64_t, uint64_t, uint64_t, uint32_t, const void*
    );
    const auto fn = reinterpret_cast<FnMsvcSyscall>(
        reinterpret_cast<const void*>(&kMsvcSyscallTrampoline[0])
    );
    return fn(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, entry.ssn, entry.gadget_addr);
#else
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    (void)arg7; (void)arg8; (void)arg9; (void)arg10; (void)arg11;
    return -1;
#endif
}

bool detect_ntdll_inline_hooks() noexcept {
    constexpr uint64_t kCriticalSyscalls[] = {
        VPACK_HASH_CI("NtQueryInformationProcess"),
        VPACK_HASH_CI("NtSetInformationThread"),
        VPACK_HASH_CI("NtQuerySystemInformation"),
        VPACK_HASH_CI("NtCreateThreadEx"),
        VPACK_HASH_CI("NtProtectVirtualMemory"),
        VPACK_HASH_CI("NtQueryVirtualMemory"),
        VPACK_HASH_CI("NtGetContextThread"),
        VPACK_HASH_CI("NtSetContextThread"),
        VPACK_HASH_CI("NtClose")
    };
    for (uint64_t h : kCriticalSyscalls) {
        SyscallEntry entry{};
        resolve_ntdll_syscall(h, entry);
        if (entry.is_hooked) {
            return true;
        }
    }
    return false;
}

VPACK_INIT_CODE bool init_jit_vcode_vault(
    uint8_t* vcode_base,
    size_t   vcode_size,
    uint64_t boot_key,
    bool     already_encrypted_by_stub
) noexcept {
    if (!vcode_base || vcode_size == 0) return false;

    acquire_jit_lock();
    if (g_vcode_jit_active.load(std::memory_order_relaxed)) {
        release_jit_lock();
        return true;
    }

    DWORD old_prot = 0;
    if (!protect_memory_via_syscall(vcode_base, vcode_size, PAGE_READWRITE, &old_prot)) {
        release_jit_lock();
        return false;
    }

    // Derive runtime-randomized pointer mask (zero static XOR mask in RAM!)
    g_jit_ptr_mask = static_cast<uintptr_t>(
        crypto::poly_permute_64(
            __rdtsc() ^ read_kuser_interrupt_time() ^ reinterpret_cast<uint64_t>(vcode_base),
            boot_key ^ 0xA59E3779B97F4A7CULL
        ) | 1ULL
    );

    // Derive initial ephemeral rolling key from RDTSC + KUSER_SHARED_DATA + boot_key
    g_vcode_rolling_key = crypto::poly_permute_64(
        __rdtsc() ^ read_kuser_interrupt_time() ^ boot_key,
        boot_key ^ 0xB7E193C58A2F4D91ULL
    );

    // Single-pass register-only trans-encryption:
    // Transitions .vcode directly from Stage 2's non-linear 64-bit boot stream into the runtime
    // JIT MBA stream while computing g_vcode_plain_hash in CPU registers so plaintext .vcode NEVER sits in RAM!
    uint64_t fnv_hash  = 0xCBF29CE484222325ULL;
    uint64_t stub_r10  = boot_key;
    uint64_t jit_state = crypto::mba_xor(g_vcode_rolling_key, 0xC983E5A19F27B4D3ULL);

    size_t words = vcode_size / 8;
    auto*  wptr  = reinterpret_cast<uint64_t*>(vcode_base);
    for (size_t i = 0; i < words; ++i) {
        uint64_t stub_ks_word = 0;
        if (already_encrypted_by_stub) {
            for (int b = 0; b < 8; ++b) {
                // Mirror of Stage 2 live re-encrypt: ror64(x,17) * M1; ^= (x>>31); += M2
                stub_r10 = rotr64(stub_r10, 17) * 0xBF58476D1CE4E5B9ULL;
                stub_r10 ^= (stub_r10 >> 31);
                stub_r10 += 0x94D049BB133111EBULL;
                stub_ks_word |= static_cast<uint64_t>(stub_r10 & 0xFFULL) << (b * 8);
            }
        }

        const uint64_t plain_word = wptr[i] ^ stub_ks_word;
        for (int b = 0; b < 8; ++b) {
            fnv_hash ^= static_cast<uint8_t>((plain_word >> (b * 8)) & 0xFFULL);
            fnv_hash *= 0x100000001B3ULL;
        }

        jit_state = crypto::mba_add(rotr64(jit_state, 17), 0x9E3779B97F4A7C15ULL * (i + 1));
        const uint64_t jit_ks_word = crypto::poly_permute_64(jit_state, g_vcode_rolling_key ^ static_cast<uint64_t>(i));
        wptr[i] = plain_word ^ jit_ks_word;
    }
    for (size_t i = words * 8; i < vcode_size; ++i) {
        uint8_t stub_ks_byte = 0;
        if (already_encrypted_by_stub) {
            stub_r10 = rotr64(stub_r10, 17) * 0xBF58476D1CE4E5B9ULL;
            stub_r10 ^= (stub_r10 >> 31);
            stub_r10 += 0x94D049BB133111EBULL;
            stub_ks_byte = static_cast<uint8_t>(stub_r10 & 0xFFULL);
        }
        const uint8_t plain_byte = static_cast<uint8_t>(vcode_base[i] ^ stub_ks_byte);
        fnv_hash ^= plain_byte;
        fnv_hash *= 0x100000001B3ULL;

        jit_state = crypto::mba_add(rotr64(jit_state, 11), 0xBF58476D1CE4E5B9ULL);
        const uint8_t jit_ks_byte = static_cast<uint8_t>((jit_state ^ (jit_state >> 29)) & 0xFFu);
        vcode_base[i] = static_cast<uint8_t>(plain_byte ^ jit_ks_byte);
    }

    g_vcode_plain_hash   = fnv_hash;
    g_vcode_encoded_base = reinterpret_cast<uintptr_t>(vcode_base) ^ g_jit_ptr_mask;
    g_vcode_size         = vcode_size;
    g_vcode_generation.store(1, std::memory_order_relaxed);
    g_vcode_cipher_hash  = crypto::fnv1a_64(vcode_base, vcode_size);

    // Lock .vcode to PAGE_READONLY (non-executable, non-writable, encrypted at rest)
    protect_memory_via_syscall(vcode_base, vcode_size, PAGE_READONLY, &old_prot);
    g_vcode_jit_active.store(true, std::memory_order_release);

    release_jit_lock();
    return true;
}

bool verify_vcode_integrity() noexcept {
    if (!g_vcode_jit_active.load(std::memory_order_acquire)) {
        return true;
    }
    if (g_vcode_tampered.load(std::memory_order_acquire)) {
        return false;
    }
    acquire_jit_lock();
    auto* base = reinterpret_cast<const uint8_t*>(g_vcode_encoded_base ^ g_jit_ptr_mask);
    uint64_t expected = (g_jit_recursion_depth == 0) ? g_vcode_cipher_hash : g_vcode_plain_hash;
    uint64_t actual   = crypto::fnv1a_64(base, g_vcode_size);
    bool ok = (actual == expected);
    if (!ok) {
        g_vcode_tampered.store(true, std::memory_order_release);
    }
    release_jit_lock();
    return ok;
}

bool rotate_vcode_idle_key() noexcept {
    if (!g_vcode_jit_active.load(std::memory_order_acquire)) {
        return false;
    }
    acquire_jit_lock();
    if (g_jit_recursion_depth == 0) {
        auto* base = reinterpret_cast<uint8_t*>(g_vcode_encoded_base ^ g_jit_ptr_mask);
        if (crypto::fnv1a_64(base, g_vcode_size) != g_vcode_cipher_hash) {
            g_vcode_tampered.store(true, std::memory_order_release);
            release_jit_lock();
            return false;
        }

        DWORD old_prot = 0;
        protect_memory_via_syscall(base, g_vcode_size, PAGE_READWRITE, &old_prot);

        const uint64_t next_gen = g_vcode_generation.fetch_add(1, std::memory_order_acq_rel) + 1;
        const uint64_t new_key  = crypto::poly_permute_64(
            g_vcode_rolling_key ^ __rdtsc() ^ read_kuser_interrupt_time(),
            next_gen ^ 0x9E3779B97F4A7C15ULL
        );

        jit_mba_homomorphic_rekey(base, g_vcode_size, g_vcode_rolling_key, new_key);
        g_vcode_rolling_key = new_key;
        g_vcode_cipher_hash = crypto::fnv1a_64(base, g_vcode_size);

        protect_memory_via_syscall(base, g_vcode_size, PAGE_READONLY, &old_prot);
    }
    release_jit_lock();
    return true;
}

uint64_t vcode_jit_generation() noexcept {
    return g_vcode_generation.load(std::memory_order_acquire);
}

bool is_vcode_jit_active() noexcept {
    return g_vcode_jit_active.load(std::memory_order_acquire);
}

bool modify_vcode_in_vault(const std::function<bool(uint8_t* vcode_base, size_t vcode_size)>& mutator) noexcept {
    if (!mutator || !g_vcode_jit_active.load(std::memory_order_acquire)) {
        return false;
    }
    acquire_jit_lock();
    bool ok = false;
    if (g_jit_recursion_depth == 0) {
        auto* base = reinterpret_cast<uint8_t*>(g_vcode_encoded_base ^ g_jit_ptr_mask);
        if (crypto::fnv1a_64(base, g_vcode_size) == g_vcode_cipher_hash) {
            DWORD old_prot = 0;
            protect_memory_via_syscall(base, g_vcode_size, PAGE_READWRITE, &old_prot);
            jit_mba_stream_transform(base, g_vcode_size, g_vcode_rolling_key);

            if (crypto::fnv1a_64(base, g_vcode_size) == g_vcode_plain_hash) {
                ok = mutator(base, g_vcode_size);
                g_vcode_plain_hash = crypto::fnv1a_64(base, g_vcode_size);
            }

            const uint64_t next_gen = g_vcode_generation.fetch_add(1, std::memory_order_acq_rel) + 1;
            g_vcode_rolling_key = crypto::poly_permute_64(
                g_vcode_rolling_key ^ __rdtsc() ^ read_kuser_interrupt_time(),
                next_gen ^ 0x9E3779B97F4A7C15ULL
            );
            jit_mba_stream_transform(base, g_vcode_size, g_vcode_rolling_key);
            g_vcode_cipher_hash = crypto::fnv1a_64(base, g_vcode_size);
            protect_memory_via_syscall(base, g_vcode_size, PAGE_READONLY, &old_prot);
            FlushInstructionCache(GetCurrentProcess(), base, g_vcode_size);
        }
    }
    release_jit_lock();
    return ok;
}

bool wipe_and_lock_vinit_section(uint8_t* vinit_base, size_t vinit_size) noexcept {
    if (!vinit_base || vinit_size == 0) return false;
    DWORD old_prot = 0;
    if (!protect_memory_via_syscall(vinit_base, vinit_size, PAGE_READWRITE, &old_prot)) {
        return false;
    }
    crypto::secure_wipe(vinit_base, vinit_size, 0xE3A985C1D72B4F89ULL ^ __rdtsc());
    protect_memory_via_syscall(vinit_base, vinit_size, PAGE_NOACCESS, &old_prot);
    return true;
}

JitSectionGuard::JitSectionGuard() noexcept {
    if (!g_vcode_jit_active.load(std::memory_order_acquire)) {
        return;
    }
    acquire_jit_lock();
    if (g_jit_recursion_depth++ == 0) {
        auto* base = reinterpret_cast<uint8_t*>(g_vcode_encoded_base ^ g_jit_ptr_mask);

        // 1. Verify at-rest ciphertext wasn't modified while locked
        if (crypto::fnv1a_64(base, g_vcode_size) != g_vcode_cipher_hash) {
            g_vcode_tampered.store(true, std::memory_order_release);
            tampered_ = true;
        }

        // 2. Temporarily unlock to RW, decrypt in-place, verify plaintext hash, then lock to RX (Zero-RWX!)
        DWORD old_prot = 0;
        protect_memory_via_syscall(base, g_vcode_size, PAGE_READWRITE, &old_prot);
        jit_mba_stream_transform(base, g_vcode_size, g_vcode_rolling_key);

        if (crypto::fnv1a_64(base, g_vcode_size) != g_vcode_plain_hash) {
            g_vcode_tampered.store(true, std::memory_order_release);
            tampered_ = true;
        }

        protect_memory_via_syscall(base, g_vcode_size, PAGE_EXECUTE_READ, &old_prot);
        FlushInstructionCache(GetCurrentProcess(), base, g_vcode_size);
    } else {
        tampered_ = g_vcode_tampered.load(std::memory_order_relaxed);
    }
}

JitSectionGuard::~JitSectionGuard() noexcept {
    if (!g_vcode_jit_active.load(std::memory_order_acquire)) {
        return;
    }
    if (--g_jit_recursion_depth == 0) {
        auto* base = reinterpret_cast<uint8_t*>(g_vcode_encoded_base ^ g_jit_ptr_mask);

        // 1. Check if a debugger planted a 0xCC breakpoint inside .vcode during execution
        if (crypto::fnv1a_64(base, g_vcode_size) != g_vcode_plain_hash) {
            g_vcode_tampered.store(true, std::memory_order_release);
        }

        // 2. Switch to RW, rotate to a brand-new ephemeral key, re-encrypt .vcode, and lock to PAGE_READONLY
        DWORD old_prot = 0;
        protect_memory_via_syscall(base, g_vcode_size, PAGE_READWRITE, &old_prot);

        const uint64_t next_gen = g_vcode_generation.fetch_add(1, std::memory_order_acq_rel) + 1;
        g_vcode_rolling_key = crypto::poly_permute_64(
            g_vcode_rolling_key ^ __rdtsc() ^ read_kuser_interrupt_time(),
            next_gen ^ 0x9E3779B97F4A7C15ULL
        );

        jit_mba_stream_transform(base, g_vcode_size, g_vcode_rolling_key);
        g_vcode_cipher_hash = crypto::fnv1a_64(base, g_vcode_size);

        protect_memory_via_syscall(base, g_vcode_size, PAGE_READONLY, &old_prot);
    }
    release_jit_lock();
}

bool query_module_layout(void* module_base, ModuleLayoutInfo& out_info) noexcept {
    if (!module_base) {
        module_base = reinterpret_cast<void*>(GetModuleHandleW(nullptr));
    }
    if (!module_base) return false;

    if (g_has_cached_layout && g_cached_main_layout.base_address == module_base) {
        out_info = g_cached_main_layout;
        return true;
    }

    auto* base = static_cast<const uint8_t*>(module_base);
    auto* dos  = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }

    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }

    out_info.base_address = module_base;
    out_info.original_size_of_image = nt->OptionalHeader.SizeOfImage;
    out_info.text_section_base = nullptr;
    out_info.text_section_size = 0;
    out_info.text_section_hash = 0;

    const IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (std::memcmp(sec->Name, ".text", 5) == 0 ||
            (sec->Characteristics & IMAGE_SCN_CNT_CODE) != 0) {
            out_info.text_section_base = base + sec->VirtualAddress;
            out_info.text_section_size = sec->Misc.VirtualSize ? sec->Misc.VirtualSize : sec->SizeOfRawData;
            out_info.text_section_hash = crypto::fnv1a_64(out_info.text_section_base, out_info.text_section_size);
            break;
        }
    }

    if (module_base == reinterpret_cast<void*>(GetModuleHandleW(nullptr))) {
        g_cached_main_layout = out_info;
        g_has_cached_layout = true;
    }

    return out_info.text_section_base != nullptr;
}

uint64_t compute_text_integrity(void* module_base) noexcept {
    if (!module_base && vault::active()) {
        return vault::cipher_hash();
    }
    ModuleLayoutInfo info{};
    if (!query_module_layout(module_base, info) || !info.text_section_base || info.text_section_size == 0) {
        return 0;
    }
    return crypto::fnv1a_64(info.text_section_base, info.text_section_size);
}

bool verify_text_integrity(uint64_t expected_hash, void* module_base) noexcept {
    if (expected_hash == 0) return false;
    return compute_text_integrity(module_base) == expected_hash && verify_vcode_integrity();
}

namespace {

// Internal CreateThread replacement backed by NtCreateThreadEx so in-process std::thread /
// _beginthreadex calls succeed even after the main module's PE headers are 100% wiped in RAM,
// while external CreateRemoteThread calls from other processes still fail with Error 193!
HANDLE WINAPI vpack_internal_create_thread(
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T                dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID                lpParameter,
    DWORD                 dwCreationFlags,
    LPDWORD               lpThreadId
) noexcept {
    (void)lpThreadAttributes;
    using FnNtCreateThreadEx = LONG(NTAPI*)(
        PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID
    );
    static auto nt_create = VPACK_IMPORT(FnNtCreateThreadEx, "ntdll.dll", "NtCreateThreadEx");
    FnNtCreateThreadEx fn = nt_create.get();
    if (!fn) return nullptr;

    const ULONG create_flags = (dwCreationFlags & CREATE_SUSPENDED) ? 0x1u : 0x0u;
    SIZE_T commit_size  = (dwStackSize != 0 && !(dwCreationFlags & STACK_SIZE_PARAM_IS_A_RESERVATION))
        ? dwStackSize : 0x10000;
    SIZE_T reserve_size = (dwStackSize != 0) ? dwStackSize : 0x100000;
    if (commit_size > reserve_size) reserve_size = commit_size;

    HANDLE hThread = nullptr;
    LONG status = fn(
        &hThread,
        THREAD_ALL_ACCESS,
        nullptr,
        GetCurrentProcess(),
        reinterpret_cast<PVOID>(lpStartAddress),
        lpParameter,
        create_flags,
        0,
        commit_size,
        reserve_size,
        nullptr
    );
    if (status != 0 || !hThread) {
        SetLastError(ERROR_BAD_EXE_FORMAT);
        return nullptr;
    }
    if (lpThreadId) {
        using FnGetThreadId = DWORD(WINAPI*)(HANDLE);
        static auto fn_gtid = VPACK_IMPORT(FnGetThreadId, "kernel32.dll", "GetThreadId");
        if (fn_gtid.get()) {
            *lpThreadId = fn_gtid(hThread);
        }
    }
    return hThread;
}

void redirect_module_createthread_iat(void* mod_base, uintptr_t target_k32, uintptr_t target_kb) noexcept {
    if (!mod_base) return;
    auto* base = static_cast<uint8_t*>(mod_base);
    auto* dos  = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    auto* nt   = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;

    const uintptr_t replacement = reinterpret_cast<uintptr_t>(&vpack_internal_create_thread);

    // 1) Redirect the PE DataDirectory IAT entry range (exact IAT, no blind scanning)
    const auto& iat_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
    if (iat_dir.VirtualAddress != 0 && iat_dir.Size >= sizeof(uintptr_t)) {
        auto* slots = reinterpret_cast<uintptr_t*>(base + iat_dir.VirtualAddress);
        const size_t count = iat_dir.Size / sizeof(uintptr_t);
        for (size_t k = 0; k < count; ++k) {
            if ((target_k32 && slots[k] == target_k32) || (target_kb && slots[k] == target_kb)) {
                DWORD old_prot = 0;
                if (protect_memory_via_syscall(&slots[k], sizeof(uintptr_t), PAGE_READWRITE, &old_prot)) {
                    slots[k] = replacement;
                    protect_memory_via_syscall(&slots[k], sizeof(uintptr_t), old_prot, &old_prot);
                }
            }
        }
    }

    // 2) Fallback: masked-boolean match across non-executable sections (covers
    //    IATs not covered by the DataDirectory IAT slot and CRT lookup tables).
    const IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) continue;
        const size_t sec_size = sec->Misc.VirtualSize ? sec->Misc.VirtualSize : sec->SizeOfRawData;
        if (sec_size < sizeof(uintptr_t)) continue;

        uint8_t* sec_ptr = base + sec->VirtualAddress;
        const size_t count = sec_size / sizeof(uintptr_t);
        auto* slots = reinterpret_cast<uintptr_t*>(sec_ptr);
        for (size_t k = 0; k < count; ++k) {
            const bool is_target = ((target_k32 != 0) & (slots[k] == target_k32)) |
                                   ((target_kb   != 0) & (slots[k] == target_kb));
            if (is_target) {
                DWORD old_prot = 0;
                if (protect_memory_via_syscall(&slots[k], sizeof(uintptr_t), PAGE_READWRITE, &old_prot)) {
                    slots[k] = replacement;
                    protect_memory_via_syscall(&slots[k], sizeof(uintptr_t), old_prot, &old_prot);
                }
            }
        }
    }
}

} // namespace

VPACK_INIT_CODE bool erase_pe_headers(void* module_base, bool keep_skeleton) noexcept {
    if (!module_base) {
        module_base = reinterpret_cast<void*>(GetModuleHandleW(nullptr));
    }
    if (!module_base) return false;

    ModuleLayoutInfo unused{};
    query_module_layout(module_base, unused);

    // Redirect in-process IAT slots for CreateThread in main module BEFORE wiping main module headers
    {
        const auto ct_k32 = reinterpret_cast<uintptr_t>(
            resolve_export_by_hash(VPACK_HASH_CI("kernel32.dll"), VPACK_HASH_CI("CreateThread"))
        );
        const auto ct_kb = reinterpret_cast<uintptr_t>(
            resolve_export_by_hash(VPACK_HASH_CI("kernelbase.dll"), VPACK_HASH_CI("CreateThread"))
        );
        if (ct_k32 || ct_kb) {
            redirect_module_createthread_iat(module_base, ct_k32, ct_kb);
        }
    }

    auto* base = static_cast<uint8_t*>(module_base);
    auto* dos  = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }

    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }

    DWORD header_size = nt->OptionalHeader.SizeOfHeaders;
    if (header_size == 0 || header_size > 0x10000) {
        header_size = 0x1000;
    }

    // Snapshot the handful of fields the minimal skeleton must keep honest:
    // the loader maps the image once at process start, but lazily-parsing
    // consumers (RtlImageNtHeader users, WinHTTP's first-call proxy init,
    // GetModuleFileName-style version walks) still re-parse these headers at
    // runtime. A 100% zeroed header region leaves them spinning forever
    // (observed: WinHttpOpen never returns), so erase everything a dumper
    // wants (DOS stub, section table, entry point, data directories) while
    // leaving a structurally valid, information-free PE skeleton.
    const LONG   lfanew          = dos->e_lfanew;
    const WORD   machine         = nt->FileHeader.Machine;
    const WORD   characteristics = nt->FileHeader.Characteristics;
    const ULONGLONG image_base   = nt->OptionalHeader.ImageBase;
    const DWORD  size_of_image   = nt->OptionalHeader.SizeOfImage;
    const DWORD  sec_align        = nt->OptionalHeader.SectionAlignment;
    const DWORD  file_align      = nt->OptionalHeader.FileAlignment;
    const WORD   subsystem        = nt->OptionalHeader.Subsystem;

    DWORD old_protect = 0;
    if (!protect_memory_via_syscall(base, header_size, PAGE_READWRITE, &old_protect)) {
        return false;
    }

    // Wipe 100% of DOS header, DOS stub, NT Headers (FileHeader + OptionalHeader + DataDirectories), and Section headers
    crypto::secure_wipe(base, header_size, 0xE3A985C1D72B4F89ULL);

    if (keep_skeleton) {
        // Optional minimal parse-safe skeleton (only when PROT_PE_SKELETON is requested):
        auto* new_dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        new_dos->e_magic  = IMAGE_DOS_SIGNATURE;
        new_dos->e_lfanew = lfanew;

        auto* new_nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + lfanew);
        new_nt->Signature                       = IMAGE_NT_SIGNATURE;
        new_nt->FileHeader.Machine              = machine;
        new_nt->FileHeader.NumberOfSections     = 0;
        new_nt->FileHeader.TimeDateStamp        = 0;
        new_nt->FileHeader.PointerToSymbolTable = 0;
        new_nt->FileHeader.NumberOfSymbols      = 0;
        new_nt->FileHeader.SizeOfOptionalHeader = sizeof(new_nt->OptionalHeader);
        new_nt->FileHeader.Characteristics      = characteristics;

        auto& opt = new_nt->OptionalHeader;
        opt.Magic                       = IMAGE_NT_OPTIONAL_HDR_MAGIC;
        opt.AddressOfEntryPoint         = 0;
        opt.BaseOfCode                  = 0;
        opt.ImageBase                   = image_base;
        opt.SectionAlignment            = sec_align;
        opt.FileAlignment               = file_align;
        opt.MajorOperatingSystemVersion = 6;
        opt.MinorOperatingSystemVersion = 1;
        opt.MajorImageVersion           = 0;
        opt.MinorImageVersion           = 0;
        opt.MajorSubsystemVersion       = 6;
        opt.MinorSubsystemVersion       = 1;
        opt.SizeOfImage                 = size_of_image;
        opt.SizeOfHeaders               = header_size;
        opt.Subsystem                   = subsystem;
        opt.DllCharacteristics          = 0;
        opt.SizeOfStackReserve          = 0;
        opt.SizeOfStackCommit           = 0;
        opt.SizeOfHeapReserve           = 0;
        opt.SizeOfHeapCommit            = 0;
        opt.LoaderFlags                 = 0;
        opt.NumberOfRvaAndSizes         = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    }

    DWORD dummy = 0;
    protect_memory_via_syscall(base, header_size, old_protect, &dummy);
    return true;
}

VPACK_INIT_CODE bool tamper_peb_image_size(uint32_t fake_size_delta) noexcept {
    uint8_t* peb = get_peb_mutable();
    if (!peb) return false;

#if defined(_M_X64) || defined(__x86_64__)
    auto* ldr = *reinterpret_cast<PebLdrDataT**>(peb + 0x18);
#else
    auto* ldr = *reinterpret_cast<PebLdrDataT**>(peb + 0x0C);
#endif
    if (!ldr) return false;

    LIST_ENTRY* head = &ldr->InLoadOrderModuleList;
    LIST_ENTRY* curr = head->Flink;
    if (!curr || curr == head) return false;

    auto* entry = reinterpret_cast<LdrDataTableEntryLoadOrderT*>(curr);
    if (g_has_cached_layout && g_cached_main_layout.original_size_of_image != 0) {
        entry->SizeOfImage = g_cached_main_layout.original_size_of_image + fake_size_delta;
    } else if (entry->SizeOfImage < 0x01000000u) {
        entry->SizeOfImage += fake_size_delta;
    }
    entry->EntryPoint = nullptr;
    return true;
}

void* resolve_export_by_hash(uint64_t module_hash_ci, uint64_t proc_hash_ci) noexcept {
    uint8_t* peb = get_peb_mutable();
    if (!peb) return nullptr;

#if defined(_M_X64) || defined(__x86_64__)
    auto* ldr = *reinterpret_cast<PebLdrDataT**>(peb + 0x18);
#else
    auto* ldr = *reinterpret_cast<PebLdrDataT**>(peb + 0x0C);
#endif
    if (!ldr) return nullptr;

    LIST_ENTRY* head = &ldr->InLoadOrderModuleList;
    for (LIST_ENTRY* it = head->Flink; it && it != head; it = it->Flink) {
        auto* entry = reinterpret_cast<LdrDataTableEntryLoadOrderT*>(it);
        if (!entry->DllBase || !entry->BaseDllName.Buffer || entry->BaseDllName.Length == 0) {
            continue;
        }

        size_t char_count = entry->BaseDllName.Length / sizeof(wchar_t);
        if (hash_unicode_ci(entry->BaseDllName.Buffer, char_count) != module_hash_ci) {
            continue;
        }

        const auto* mod_base = static_cast<const uint8_t*>(entry->DllBase);
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(mod_base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) continue;

        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(mod_base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) continue;

        const auto& exp_dir_entry = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (exp_dir_entry.VirtualAddress == 0 || exp_dir_entry.Size == 0) continue;

        const auto* exp_dir = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(mod_base + exp_dir_entry.VirtualAddress);
        const auto* names   = reinterpret_cast<const DWORD*>(mod_base + exp_dir->AddressOfNames);
        const auto* funcs   = reinterpret_cast<const DWORD*>(mod_base + exp_dir->AddressOfFunctions);
        const auto* ords    = reinterpret_cast<const WORD*>(mod_base + exp_dir->AddressOfNameOrdinals);

        for (DWORD i = 0; i < exp_dir->NumberOfNames; ++i) {
            const char* fn_name = reinterpret_cast<const char*>(mod_base + names[i]);
            if (crypto::fnv1a_64_ci(fn_name) == proc_hash_ci) {
                WORD ordinal = ords[i];
                DWORD func_rva = funcs[ordinal];

                // Check if forwarded export
                if (func_rva >= exp_dir_entry.VirtualAddress &&
                    func_rva < exp_dir_entry.VirtualAddress + exp_dir_entry.Size) {
                    return reinterpret_cast<void*>(GetProcAddress(
                        reinterpret_cast<HMODULE>(entry->DllBase),
                        fn_name
                    ));
                }
                return const_cast<uint8_t*>(mod_base + func_rva);
            }
        }
    }

    return nullptr;
}

} // namespace vpack::antidump
