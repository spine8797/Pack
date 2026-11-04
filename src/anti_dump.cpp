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

constexpr size_t kMaxBaselineModules = 128;
void*            g_baseline_modules[kMaxBaselineModules]{};
size_t           g_baseline_module_count = 0;

// ============================================================================
// JIT .vcode Vault State (Obfuscated in RAM)
// ============================================================================
constexpr uintptr_t kJitPtrMask = static_cast<uintptr_t>(0xA59E3779B97F4A7CULL);

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

} // namespace

bool resolve_ntdll_syscall(uint64_t proc_hash_ci, SyscallEntry& out_entry) noexcept {
    out_entry = SyscallEntry{};
    void* raw_fn = resolve_export_by_hash(VPACK_HASH_CI("ntdll.dll"), proc_hash_ci);
    if (!raw_fn) return false;

    const auto* fn_bytes = static_cast<const uint8_t*>(raw_fn);

    // 1. Direct inspection if unhooked
    if (is_clean_syscall_prologue(fn_bytes)) {
        out_entry.ssn         = *reinterpret_cast<const uint32_t*>(fn_bytes + 4);
        out_entry.gadget_addr = find_syscall_ret_gadget(fn_bytes);
        out_entry.is_hooked   = false;
    } else {
        // 2. HalosGate / Tartarus' Gate: function is hooked (e.g. ScyllaHide JMP at +0x00 or +0x03).
        // Scan neighboring ntdll syscall stubs (+/- 32-byte stride) to recover exact SSN & clean gadget!
        out_entry.is_hooked = true;
        constexpr intptr_t kStubStride = 32;
        for (int idx = 1; idx <= 64; ++idx) {
            // Check downward neighbor (+idx * 32)
            const uint8_t* down = fn_bytes + idx * kStubStride;
            if (is_clean_syscall_prologue(down)) {
                uint32_t neighbor_ssn = *reinterpret_cast<const uint32_t*>(down + 4);
                if (neighbor_ssn >= static_cast<uint32_t>(idx)) {
                    out_entry.ssn         = neighbor_ssn - static_cast<uint32_t>(idx);
                    out_entry.gadget_addr = find_syscall_ret_gadget(down);
                    break;
                }
            }
            // Check upward neighbor (-idx * 32)
            const uint8_t* up = fn_bytes - idx * kStubStride;
            if (is_clean_syscall_prologue(up)) {
                uint32_t neighbor_ssn = *reinterpret_cast<const uint32_t*>(up + 4);
                out_entry.ssn         = neighbor_ssn + static_cast<uint32_t>(idx);
                out_entry.gadget_addr = find_syscall_ret_gadget(up);
                break;
            }
        }
    }

    // If gadget wasn't in the immediate stub, scan nearby ntdll stubs for any `0F 05 C3`
    if (!out_entry.gadget_addr) {
        for (int idx = 1; idx <= 64; ++idx) {
            if (const void* g = find_syscall_ret_gadget(fn_bytes + idx * 32)) {
                out_entry.gadget_addr = g;
                break;
            }
        }
    }

    return out_entry.ssn != 0xFFFFFFFFu && out_entry.gadget_addr != nullptr;
}

VPACK_NOINLINE long invoke_indirect_syscall(
    const SyscallEntry& entry,
    uint64_t arg1,
    uint64_t arg2,
    uint64_t arg3,
    uint64_t arg4,
    uint64_t arg5,
    uint64_t arg6
) noexcept {
    if (!entry.gadget_addr || entry.ssn == 0xFFFFFFFFu) {
        return -1;
    }
#if (defined(__GNUC__) || defined(__clang__)) && (defined(__x86_64__) || defined(_M_X64))
    long status = -1;
    const void* gadget = entry.gadget_addr;
    register uint64_t r10_reg __asm__("r10") = arg1;
    register uint64_t rcx_reg __asm__("rcx") = arg1;
    register uint64_t rdx_reg __asm__("rdx") = arg2;
    register uint64_t r8_reg  __asm__("r8")  = arg3;
    register uint64_t r9_reg  __asm__("r9")  = arg4;
    register uint32_t eax_reg __asm__("eax") = entry.ssn;

    __asm__ volatile(
        "subq $0x38, %%rsp\n\t"
        "movq %[a5], 0x20(%%rsp)\n\t"
        "movq %[a6], 0x28(%%rsp)\n\t"
        "callq *%[gad]\n\t"
        "addq $0x38, %%rsp\n\t"
        : "=a"(status), "+r"(rcx_reg), "+r"(rdx_reg), "+r"(r8_reg), "+r"(r9_reg), "+r"(r10_reg)
        : "0"(eax_reg), [gad] "r"(gadget), [a5] "r"(arg5), [a6] "r"(arg6)
        : "memory", "cc", "r11"
    );
    return status;
#else
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
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

    // Derive initial ephemeral rolling key from RDTSC + KUSER_SHARED_DATA + boot_key
    g_vcode_rolling_key = crypto::poly_permute_64(
        __rdtsc() ^ read_kuser_interrupt_time() ^ boot_key,
        boot_key ^ 0xB7E193C58A2F4D91ULL
    );

    // Single-pass register-only trans-encryption:
    // Transitions .vcode directly from Stage 2's boot stream into the runtime JIT MBA stream
    // while computing g_vcode_plain_hash in CPU registers so plaintext .vcode NEVER sits in RAM!
    uint64_t fnv_hash  = 0xCBF29CE484222325ULL;
    uint64_t stub_r10  = boot_key;
    uint64_t jit_state = crypto::mba_xor(g_vcode_rolling_key, 0xC983E5A19F27B4D3ULL);

    size_t words = vcode_size / 8;
    auto*  wptr  = reinterpret_cast<uint64_t*>(vcode_base);
    for (size_t i = 0; i < words; ++i) {
        uint64_t stub_ks_word = 0;
        if (already_encrypted_by_stub) {
            for (int b = 0; b < 8; ++b) {
                stub_r10 = rotr64(stub_r10, 13) + 0x9E3779B97F4A7C15ULL;
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
            stub_r10 = rotr64(stub_r10, 13) + 0x9E3779B97F4A7C15ULL;
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
    g_vcode_encoded_base = reinterpret_cast<uintptr_t>(vcode_base) ^ kJitPtrMask;
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
    auto* base = reinterpret_cast<const uint8_t*>(g_vcode_encoded_base ^ kJitPtrMask);
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
        auto* base = reinterpret_cast<uint8_t*>(g_vcode_encoded_base ^ kJitPtrMask);
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
        auto* base = reinterpret_cast<uint8_t*>(g_vcode_encoded_base ^ kJitPtrMask);

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
        auto* base = reinterpret_cast<uint8_t*>(g_vcode_encoded_base ^ kJitPtrMask);

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

VPACK_INIT_CODE bool erase_pe_headers(void* module_base) noexcept {
    if (!module_base) {
        module_base = reinterpret_cast<void*>(GetModuleHandleW(nullptr));
    }
    if (!module_base) return false;

    ModuleLayoutInfo unused{};
    query_module_layout(module_base, unused);

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

    DWORD old_protect = 0;
    if (!protect_memory_via_syscall(base, header_size, PAGE_READWRITE, &old_protect)) {
        return false;
    }

    // Wipe 100% of DOS header, DOS stub, NT Headers (FileHeader + OptionalHeader + DataDirectories), and Section headers
    crypto::secure_wipe(base, header_size, 0xE3A985C1D72B4F89ULL);

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
    entry->SizeOfImage += fake_size_delta;
    entry->EntryPoint   = nullptr;
    return true;
}

VPACK_INIT_CODE uint32_t capture_module_baseline() noexcept {
    g_baseline_module_count = 0;
    uint8_t* peb = get_peb_mutable();
    if (!peb) return 0;

#if defined(_M_X64) || defined(__x86_64__)
    auto* ldr = *reinterpret_cast<PebLdrDataT**>(peb + 0x18);
#else
    auto* ldr = *reinterpret_cast<PebLdrDataT**>(peb + 0x0C);
#endif
    if (!ldr) return 0;

    LIST_ENTRY* head = &ldr->InLoadOrderModuleList;
    for (LIST_ENTRY* it = head->Flink; it && it != head; it = it->Flink) {
        auto* entry = reinterpret_cast<LdrDataTableEntryLoadOrderT*>(it);
        if (entry->DllBase && g_baseline_module_count < kMaxBaselineModules) {
            g_baseline_modules[g_baseline_module_count++] = entry->DllBase;
        }
    }
    return static_cast<uint32_t>(g_baseline_module_count);
}

bool detect_injected_module(void** out_base, char* out_name, size_t max_len) noexcept {
    if (g_baseline_module_count == 0) return false;
    uint8_t* peb = get_peb_mutable();
    if (!peb) return false;

#if defined(_M_X64) || defined(__x86_64__)
    auto* ldr = *reinterpret_cast<PebLdrDataT**>(peb + 0x18);
#else
    auto* ldr = *reinterpret_cast<PebLdrDataT**>(peb + 0x0C);
#endif
    if (!ldr) return false;

    LIST_ENTRY* head = &ldr->InLoadOrderModuleList;
    for (LIST_ENTRY* it = head->Flink; it && it != head; it = it->Flink) {
        auto* entry = reinterpret_cast<LdrDataTableEntryLoadOrderT*>(it);
        if (!entry->DllBase) continue;

        bool known = false;
        for (size_t i = 0; i < g_baseline_module_count; ++i) {
            if (g_baseline_modules[i] == entry->DllBase) {
                known = true;
                break;
            }
        }

        if (!known) {
            if (out_base) *out_base = entry->DllBase;
            if (out_name && max_len > 0) {
                size_t chars = entry->BaseDllName.Length / sizeof(wchar_t);
                size_t copy_len = (chars < max_len - 1) ? chars : (max_len - 1);
                for (size_t c = 0; c < copy_len; ++c) {
                    out_name[c] = static_cast<char>(entry->BaseDllName.Buffer[c] & 0xFF);
                }
                out_name[copy_len] = '\0';
            }
            return true;
        }
    }
    return false;
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
