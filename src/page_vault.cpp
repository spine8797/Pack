// page_vault.cpp — no-thread FIFO-window lazy page vault (.vpvlt isolated section + Indirect Syscall)
#include "vpack/page_vault.h"
#include "vpack/anti_dump.h"
#include "vpack/config.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <intrin.h>

#ifndef VPACK_VAULT_WINDOW
#define VPACK_VAULT_WINDOW 8      // maximum simultaneously decrypted .text pages
#endif

namespace vpack::vault {

namespace {

constexpr size_t    kPageSize     = 0x1000;
constexpr size_t    kMaxPages     = 2048;              // <= 8 MB code
constexpr size_t    kWindow       = VPACK_VAULT_WINDOW;
constexpr uint64_t  kGold         = 0x9E3779B97F4A7C15ULL;
constexpr uint64_t  kM1           = 0xBF58476D1CE4E5B9ULL;
constexpr uint64_t  kM2           = 0x94D049BB133111EBULL;

uintptr_t        g_vault_ptr_mask    = 0;   // Runtime-generated mask (never static in binary!)
uint8_t*         g_base              = nullptr;
size_t           g_size              = 0;
uint64_t         g_ntdll_base        = 0;
uint64_t         g_ntdll_end         = 0;
uint64_t         g_seed              = 0;
uintptr_t        g_cipher_encoded    = 0;   // XOR-masked heap pointer, PAGE_NOACCESS when idle
uint32_t         g_sc_protect_ssn    = 0xFFFFFFFFu;
uintptr_t        g_sc_protect_gadget = 0;   // XOR-masked `syscall; ret` gadget inside ntdll.dll
size_t           g_pages             = 0;
volatile LONG    g_installed         = 0;
volatile LONG    g_lock_init         = 0;
CRITICAL_SECTION g_cs{};
PVOID            g_veh               = nullptr;
uint64_t         g_hash              = 0;

// FIFO window of currently decrypted plaintext pages: [0] = oldest
volatile uint64_t g_window[kWindow]{};
size_t            g_window_n = 0;

#if defined(_MSC_VER) && defined(_M_X64)
#pragma section(".vpvlt", execute, read)
#pragma code_seg(".vpvlt")
__declspec(allocate(".vpvlt")) alignas(16) const uint8_t kVaultMsvcSyscallStub[16] = {
    0x4C, 0x8B, 0xD1,             // mov r10, rcx
    0x8B, 0x44, 0x24, 0x38,       // mov eax, dword ptr [rsp + 0x38] (ssn)
    0xFF, 0x64, 0x24, 0x40,       // jmp qword ptr [rsp + 0x40]      (gadget_addr in ntdll)
    0xC3, 0x90, 0x90, 0x90, 0x90
};
#pragma code_seg()
#endif

VPACK_FORCEINLINE uint8_t* decode_cipher_ptr() noexcept {
    if (g_cipher_encoded == 0) return nullptr;
    return reinterpret_cast<uint8_t*>(g_cipher_encoded ^ g_vault_ptr_mask);
}

VPACK_FORCEINLINE void ensure_lock() noexcept {
    if (InterlockedCompareExchange(&g_lock_init, 1, 0) == 0) {
        InitializeCriticalSection(&g_cs);
    }
}

VPACK_FORCEINLINE uint64_t splitmix_step(uint64_t& st) noexcept {
    uint64_t z = st;
    z ^= z >> 30;
    st += kGold;
    z *= kM1;
    z ^= z >> 27;
    z *= kM2;
    return z ^ (z >> 31);
}

// Per-page keystream seed (identical between install encryption and VEH decryption)
VPACK_FORCEINLINE uint64_t page_seed(size_t idx) noexcept {
    uint64_t st = g_seed ^ (static_cast<uint64_t>(idx) * kPageSize);
    splitmix_step(st);
    return st;
}

VPACK_FORCEINLINE void vault_zero_page(void* page_ptr) noexcept {
    volatile uint64_t* z = static_cast<volatile uint64_t*>(page_ptr);
    for (size_t i = 0; i < kPageSize / sizeof(uint64_t); ++i) {
        z[i] = 0;
    }
}

// Executes NtProtectVirtualMemory via Indirect Syscall directly from .vpvlt so user-mode
// hooks on kernel32!VirtualProtect or ntdll!NtProtectVirtualMemory NEVER see g_cipher!
VPACK_VAULT_CODE bool vault_protect_memory(void* addr, size_t len, DWORD new_prot, DWORD* out_old) noexcept {
    DWORD dummy_old = 0;
    DWORD* old_ptr  = out_old ? out_old : &dummy_old;

    if (g_sc_protect_ssn != 0xFFFFFFFFu && g_sc_protect_gadget != 0) {
        const void* gadget = reinterpret_cast<const void*>(g_sc_protect_gadget ^ g_vault_ptr_mask);
        PVOID  region_base = addr;
        SIZE_T region_size = len;
        ULONG  old_p       = 0;
        long   status      = -1;

#if (defined(__GNUC__) || defined(__clang__)) && (defined(__x86_64__) || defined(_M_X64))
        register uint64_t r10_reg __asm__("r10") = ~0ULL; // NtCurrentProcess() = (HANDLE)-1
        register uint64_t rcx_reg __asm__("rcx") = ~0ULL;
        register uint64_t rdx_reg __asm__("rdx") = reinterpret_cast<uint64_t>(&region_base);
        register uint64_t r8_reg  __asm__("r8")  = reinterpret_cast<uint64_t>(&region_size);
        register uint64_t r9_reg  __asm__("r9")  = static_cast<uint64_t>(new_prot);
        register uint32_t eax_reg __asm__("eax") = g_sc_protect_ssn;
        register uint64_t rsi_arg5 __asm__("rsi") = reinterpret_cast<uint64_t>(&old_p);
        register const void* rdi_gad __asm__("rdi") = gadget;

        __asm__ volatile(
            "subq $0x38, %%rsp\n\t"
            "movq %%rsi, 0x20(%%rsp)\n\t"
            "callq *%%rdi\n\t"
            "addq $0x38, %%rsp\n\t"
            : "=a"(status), "+r"(rcx_reg), "+r"(rdx_reg), "+r"(r8_reg), "+r"(r9_reg), "+r"(r10_reg)
            : "0"(eax_reg), "r"(rdi_gad), "r"(rsi_arg5)
            : "memory", "cc", "r11"
        );
#elif defined(_MSC_VER) && defined(_M_X64)
        using FnVaultSc = long(*)(
            uint64_t, uint64_t, uint64_t, uint64_t,
            uint64_t, uint64_t, uint32_t, const void*
        );
        const auto fn_sc = reinterpret_cast<FnVaultSc>(
            reinterpret_cast<const void*>(&kVaultMsvcSyscallStub[0])
        );
        status = fn_sc(
            ~0ULL,
            reinterpret_cast<uint64_t>(&region_base),
            reinterpret_cast<uint64_t>(&region_size),
            static_cast<uint64_t>(new_prot),
            reinterpret_cast<uint64_t>(&old_p),
            0ULL,
            g_sc_protect_ssn,
            gadget
        );
#endif
        if (status == 0) {
            *old_ptr = static_cast<DWORD>(old_p);
            return true;
        }
    }

    return VirtualProtect(addr, len, new_prot, old_ptr) != 0;
}

VPACK_VAULT_CODE uint64_t fnv1a_vault(const uint8_t* p, size_t n) noexcept {
    uint64_t h = 0xCBF29CE484222325ULL;
    for (size_t i = 0; i < n; ++i) {
        h ^= p[i];
        h *= 0x100000001B3ULL;
    }
    return h;
}

VPACK_VAULT_CODE void retire_page_locked(uint64_t page) noexcept {
    DWORD old = 0;
    if (vault_protect_memory(reinterpret_cast<void*>(page), kPageSize, PAGE_READWRITE, &old)) {
        vault_zero_page(reinterpret_cast<void*>(page));
        vault_protect_memory(reinterpret_cast<void*>(page), kPageSize, PAGE_NOACCESS, &old);
    }
}

VPACK_VAULT_CODE bool decrypt_page_locked(uint64_t page, uint64_t active_rip_page) noexcept {
    const uint64_t base64 = reinterpret_cast<uint64_t>(g_base);
    const size_t idx = static_cast<size_t>((page - base64) / kPageSize);
    if (idx >= g_pages) return false;

    for (size_t i = 0; i < g_window_n; ++i) {
        if (g_window[i] == page) {
            return true;
        }
    }

    uint8_t* cipher_base = decode_cipher_ptr();
    if (!cipher_base) return false;

    uint8_t* src = cipher_base + idx * kPageSize;
    DWORD old = 0;
    if (!vault_protect_memory(src, kPageSize, PAGE_READONLY, &old)) return false;
    if (!vault_protect_memory(reinterpret_cast<void*>(page), kPageSize, PAGE_READWRITE, &old)) {
        vault_protect_memory(src, kPageSize, PAGE_NOACCESS, &old);
        return false;
    }

    volatile uint8_t* dst = reinterpret_cast<volatile uint8_t*>(page);
    uint64_t st = page_seed(idx);
    for (size_t i = 0; i < kPageSize; ++i) {
        uint8_t ks = static_cast<uint8_t>(splitmix_step(st) & 0xFFu);
        dst[i] = static_cast<uint8_t>(src[i] ^ ks);
    }
    vault_protect_memory(reinterpret_cast<void*>(page), kPageSize, PAGE_EXECUTE_READ, &old);
    vault_protect_memory(src, kPageSize, PAGE_NOACCESS, &old);
    FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(page), kPageSize);

    // FIFO window: if full, retire the oldest page (skipping active_rip_page on cross-page straddle/read)
    if (g_window_n == kWindow) {
        size_t evict_idx = (g_window[0] == active_rip_page && g_window_n > 1) ? 1 : 0;
        retire_page_locked(g_window[evict_idx]);
        for (size_t i = evict_idx + 1; i < g_window_n; ++i) {
            g_window[i - 1] = g_window[i];
        }
        --g_window_n;
    }
    g_window[g_window_n++] = page;
    return true;
}

VPACK_VAULT_CODE LONG CALLBACK veh(PEXCEPTION_POINTERS ex) noexcept {
    if (ex->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION)
        return EXCEPTION_CONTINUE_SEARCH;
    if (!g_installed) return EXCEPTION_CONTINUE_SEARCH;

    const ULONG_PTR access_type = ex->ExceptionRecord->ExceptionInformation[0];
    const uint64_t  fault       = static_cast<uint64_t>(ex->ExceptionRecord->ExceptionInformation[1]);
    const uint64_t  page        = fault & ~static_cast<uint64_t>(kPageSize - 1);
    const uint64_t  base        = reinterpret_cast<uint64_t>(g_base);
    if (page < base || page >= base + g_size) return EXCEPTION_CONTINUE_SEARCH;

    // Serve instruction fetch faults and legitimate internal .text / SEH unwind reads:
    //  1) RIP is inside the faulting page, OR
    //  2) RIP is at the end of the preceding page (within 15 bytes) and straddles into `page`, OR
    //  3) Hardware DEP/NX execute fault (access_type == 8) where RIP is in the vaulted range, OR
    //  4) Read fault (access_type == 0) where RIP is inside the vaulted .text range [base, base + g_size), OR
    //  5) Read fault (access_type == 0) from ntdll.dll (e.g. RtlVirtualUnwind inspecting function epilogues
    //     during C++ try/catch or SEH stack unwinding).
    const uint64_t rip           = static_cast<uint64_t>(ex->ContextRecord->Rip);
    const uint64_t rip_page      = rip & ~static_cast<uint64_t>(kPageSize - 1);
    const bool     same_page     = (rip_page == page);
    const bool     straddle      = (rip < page) && (rip + 16 >= page) && (rip >= base);
    const bool     exec_fault    = (access_type == 8) && (rip >= base && rip < base + g_size);
    const bool     internal_read = (access_type == 0) && (rip >= base && rip < base + g_size);
    const bool     ntdll_unwind  = (access_type == 0) && (rip >= g_ntdll_base && rip < g_ntdll_end);
    if (!same_page && !straddle && !exec_fault && !internal_read && !ntdll_unwind)
        return EXCEPTION_CONTINUE_SEARCH;

    ensure_lock();
    EnterCriticalSection(&g_cs);
    const bool ok = decrypt_page_locked(page, rip_page);
    LeaveCriticalSection(&g_cs);
    return ok ? EXCEPTION_CONTINUE_EXECUTION : EXCEPTION_CONTINUE_SEARCH;
}

} // namespace

VPACK_VAULT_CODE bool install(void* code_base, size_t code_size,
                              const uint8_t* cipher, uint64_t master_seed) noexcept {
    if (!code_base || code_size == 0) return false;
    if (g_installed) return true;

    const uint64_t base = reinterpret_cast<uint64_t>(code_base);
    if (base & (kPageSize - 1)) return false;

    const size_t pages = (code_size + kPageSize - 1) / kPageSize;
    if (pages == 0 || pages > kMaxPages) return false;

    // Generate runtime-unique pointer mask (zero static XOR constant in RAM!)
    const volatile uint64_t* kuser_time = reinterpret_cast<const volatile uint64_t*>(0x7FFE0008ULL);
    uint64_t dyn_m = __rdtsc() ^ (*kuser_time) ^ master_seed ^ reinterpret_cast<uint64_t>(code_base) ^ 0xD39A81E5C72B4F91ULL;
    g_vault_ptr_mask = static_cast<uintptr_t>(splitmix_step(dyn_m) | 1ULL);

    // Resolve NtProtectVirtualMemory indirect syscall once before locking .text pages
    antidump::SyscallEntry sc_prot{};
    if (antidump::resolve_ntdll_syscall(VPACK_HASH_CI("NtProtectVirtualMemory"), sc_prot) &&
        sc_prot.gadget_addr && sc_prot.ssn != 0xFFFFFFFFu) {
        g_sc_protect_ssn    = sc_prot.ssn;
        g_sc_protect_gadget = reinterpret_cast<uintptr_t>(sc_prot.gadget_addr) ^ g_vault_ptr_mask;
    }

    // Cache exact RtlVirtualUnwind bounds (+4KB) in ntdll.dll so ONLY SEH/C++ stack unwinding
    // can read evicted .text epilogue bytes (blocks ntdll!memcpy / RtlMoveMemory gadgets)
    if (void* unwind_fn = antidump::resolve_export_by_hash(
            VPACK_HASH_CI("ntdll.dll"), VPACK_HASH_CI("RtlVirtualUnwind"))) {
        g_ntdll_base = reinterpret_cast<uint64_t>(unwind_fn);
        g_ntdll_end  = g_ntdll_base + 0x1000ULL;
    }

    ensure_lock();
    EnterCriticalSection(&g_cs);

    g_base     = static_cast<uint8_t*>(code_base);
    g_size     = pages * kPageSize;
    g_seed     = master_seed ^ 0xA59E3779B97F4A7CULL;
    g_pages    = pages;
    g_window_n = 0;

    uint8_t* cipher_buf = static_cast<uint8_t*>(
        VirtualAlloc(nullptr, pages * kPageSize, MEM_COMMIT | MEM_RESERVE,
                     PAGE_READWRITE));
    if (!cipher_buf) {
        LeaveCriticalSection(&g_cs);
        return false;
    }

    if (cipher) {
        for (size_t b = 0; b < pages * kPageSize; ++b) {
            cipher_buf[b] = cipher[b];
        }
    } else {
        // Live per-page encryption from relocated .text in RAM
        for (size_t idx = 0; idx < pages; ++idx) {
            uint64_t st = page_seed(idx);
            const uint8_t* src_page = g_base + idx * kPageSize;
            uint8_t*       dst_page = cipher_buf + idx * kPageSize;
            for (size_t i = 0; i < kPageSize; ++i) {
                uint8_t ks = static_cast<uint8_t>(splitmix_step(st) & 0xFFu);
                dst_page[i] = static_cast<uint8_t>(src_page[i] ^ ks);
            }
        }
    }

    g_hash           = fnv1a_vault(cipher_buf, pages * kPageSize);
    g_cipher_encoded = reinterpret_cast<uintptr_t>(cipher_buf) ^ g_vault_ptr_mask;

    g_veh = AddVectoredExceptionHandler(1, veh);
    InterlockedExchange(&g_installed, 1);

    DWORD old = 0;
    vault_protect_memory(cipher_buf, pages * kPageSize, PAGE_NOACCESS, &old);

    // Keep the immediate caller page in window[0] so return from install() doesn't fault mid-epilogue;
    // all other pages of .text are immediately zeroed and locked to PAGE_NOACCESS via Indirect Syscall!
#if defined(_MSC_VER)
    const void* ret_addr = _ReturnAddress();
#else
    const void* ret_addr = __builtin_extract_return_addr(__builtin_return_address(0));
#endif
    const uint64_t caller_page = reinterpret_cast<uint64_t>(ret_addr) & ~static_cast<uint64_t>(kPageSize - 1);
    const uint64_t veh_page    = reinterpret_cast<uint64_t>(&veh) & ~static_cast<uint64_t>(kPageSize - 1);
    const uint64_t dec_page    = reinterpret_cast<uint64_t>(&decrypt_page_locked) & ~static_cast<uint64_t>(kPageSize - 1);

    for (size_t i = 0; i < pages; ++i) {
        const uint64_t cur_page = base + i * kPageSize;
        if (cur_page == veh_page || cur_page == dec_page) {
            continue;
        }
        if (cur_page == caller_page && g_window_n < kWindow) {
            g_window[g_window_n++] = cur_page;
            continue;
        }
        if (vault_protect_memory(reinterpret_cast<void*>(cur_page), kPageSize, PAGE_READWRITE, &old)) {
            vault_zero_page(reinterpret_cast<void*>(cur_page));
            vault_protect_memory(reinterpret_cast<void*>(cur_page), kPageSize, PAGE_NOACCESS, &old);
        }
    }

    LeaveCriticalSection(&g_cs);
    return true;
}

VPACK_VAULT_CODE void sync_modified_range(const void* address, size_t size) noexcept {
    if (!g_installed || !address || size == 0) return;

    ensure_lock();
    EnterCriticalSection(&g_cs);

    const uint64_t base  = reinterpret_cast<uint64_t>(g_base);
    const uint64_t start = reinterpret_cast<uint64_t>(address);
    const uint64_t end   = start + size;

    if (end <= base || start >= base + g_size) {
        LeaveCriticalSection(&g_cs);
        return;
    }

    uint8_t* cipher_buf = decode_cipher_ptr();
    if (!cipher_buf) {
        LeaveCriticalSection(&g_cs);
        return;
    }

    DWORD old = 0;
    if (vault_protect_memory(cipher_buf, g_size, PAGE_READWRITE, &old)) {
        const uint64_t first_page = (start > base ? start : base) & ~static_cast<uint64_t>(kPageSize - 1);
        const uint64_t last_page  = ((end < base + g_size ? end : base + g_size) - 1) & ~static_cast<uint64_t>(kPageSize - 1);

        for (uint64_t page = first_page; page <= last_page; page += kPageSize) {
            const size_t idx = static_cast<size_t>((page - base) / kPageSize);
            if (idx >= g_pages) break;
            if (!decrypt_page_locked(page, first_page)) continue;

            uint64_t st = page_seed(idx);
            const uint8_t* src_plain = reinterpret_cast<const uint8_t*>(page);
            uint8_t*       dst_ciph  = cipher_buf + idx * kPageSize;
            for (size_t i = 0; i < kPageSize; ++i) {
                uint8_t ks = static_cast<uint8_t>(splitmix_step(st) & 0xFFu);
                dst_ciph[i] = static_cast<uint8_t>(src_plain[i] ^ ks);
            }
        }

        g_hash = fnv1a_vault(cipher_buf, g_size);
        vault_protect_memory(cipher_buf, g_size, PAGE_NOACCESS, &old);
    }

    LeaveCriticalSection(&g_cs);
}

VPACK_VAULT_CODE void uninstall() noexcept {
    ensure_lock();
    EnterCriticalSection(&g_cs);
    InterlockedExchange(&g_installed, 0);

    uint8_t* cipher_buf = decode_cipher_ptr();
    if (g_base && g_size && cipher_buf) {
        DWORD old = 0;
        vault_protect_memory(cipher_buf, g_size, PAGE_READONLY, &old);
        vault_protect_memory(g_base, g_size, PAGE_READWRITE, &old);
        for (size_t idx = 0; idx < g_pages; ++idx) {
            uint64_t st = page_seed(idx);
            const uint8_t* src = cipher_buf + idx * kPageSize;
            uint8_t*       dst = g_base + idx * kPageSize;
            for (size_t i = 0; i < kPageSize; ++i) {
                uint8_t ks = static_cast<uint8_t>(splitmix_step(st) & 0xFFu);
                dst[i] = static_cast<uint8_t>(src[i] ^ ks);
            }
        }
        vault_protect_memory(g_base, g_size, PAGE_EXECUTE_READ, &old);
        FlushInstructionCache(GetCurrentProcess(), g_base, g_size);
    }

    if (g_veh) {
        RemoveVectoredExceptionHandler(g_veh);
        g_veh = nullptr;
    }
    if (cipher_buf) {
        VirtualFree(cipher_buf, 0, MEM_RELEASE);
        g_cipher_encoded = 0;
    }

    g_base     = nullptr;
    g_size     = 0;
    g_pages    = 0;
    g_window_n = 0;
    LeaveCriticalSection(&g_cs);
}

VPACK_VAULT_CODE bool active() noexcept {
    return g_installed != 0;
}

VPACK_VAULT_CODE uint64_t cipher_hash() noexcept {
    if (!g_installed) return g_hash;

    ensure_lock();
    EnterCriticalSection(&g_cs);

    uint64_t result = g_hash;
    uint8_t* cipher_buf = decode_cipher_ptr();
    const uint64_t base = reinterpret_cast<uint64_t>(g_base);

    if (cipher_buf && g_base) {
        bool tampered = false;
        for (size_t w = 0; w < g_window_n; ++w) {
            const uint64_t page = g_window[w];
            if (page < base || page >= base + g_size) continue;
            const size_t idx = static_cast<size_t>((page - base) / kPageSize);
            if (idx >= g_pages) continue;

            uint8_t* src = cipher_buf + idx * kPageSize;
            DWORD old = 0;
            if (vault_protect_memory(src, kPageSize, PAGE_READONLY, &old)) {
                const uint8_t* dst = reinterpret_cast<const uint8_t*>(page);
                uint64_t st = page_seed(idx);
                for (size_t i = 0; i < kPageSize; ++i) {
                    uint8_t ks = static_cast<uint8_t>(splitmix_step(st) & 0xFFu);
                    if (static_cast<uint8_t>(dst[i] ^ ks) != src[i]) {
                        tampered = true;
                        break;
                    }
                }
                vault_protect_memory(src, kPageSize, PAGE_NOACCESS, &old);
            }
            if (tampered) break;
        }
        if (tampered) {
            result ^= 0xBAD0C0DEDEAD10CCULL;
        }
    }

    LeaveCriticalSection(&g_cs);
    return result;
}

} // namespace vpack::vault
