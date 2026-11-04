// page_vault.cpp — no-thread FIFO-window lazy page vault
#include "vpack/page_vault.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstring>

#ifndef VPACK_VAULT_WINDOW
#define VPACK_VAULT_WINDOW 4      // so trang plaintext toi da cung luc
#endif

namespace vpack::vault {

namespace {

constexpr size_t   kPageSize   = 0x1000;
constexpr size_t   kMaxPages   = 2048;              // <= 8 MB code
constexpr size_t   kWindow     = VPACK_VAULT_WINDOW;
constexpr uint64_t kGold       = 0x9E3779B97F4A7C15ULL;
constexpr uint64_t kM1         = 0xBF58476D1CE4E5B9ULL;
constexpr uint64_t kM2         = 0x94D049BB133111EBULL;

uint8_t*         g_base    = nullptr;
size_t           g_size    = 0;
uint64_t         g_seed    = 0;
uint8_t*         g_cipher  = nullptr;   // heap, PAGE_NOACCESS khi idle
size_t           g_pages   = 0;
volatile LONG    g_installed = 0;
volatile LONG    g_lock_init = 0;
CRITICAL_SECTION g_cs{};
PVOID            g_veh = nullptr;
uint64_t         g_hash  = 0;

// FIFO window cac trang dang plaintext: [0] = cu nhat
uint64_t g_window[kWindow]{};
size_t   g_window_n = 0;

inline void ensure_lock() noexcept {
    if (InterlockedCompareExchange(&g_lock_init, 1, 0) == 0) {
        InitializeCriticalSection(&g_cs);
    }
}

inline uint64_t splitmix_step(uint64_t& st) noexcept {
    uint64_t z = st;
    z ^= z >> 30;
    st += kGold;
    z *= kM1;
    z ^= z >> 27;
    z *= kM2;
    return z ^ (z >> 31);
}

// seed rieng tung trang (phai giong packer)
uint64_t page_seed(size_t idx) noexcept {
    uint64_t st = g_seed ^ (static_cast<uint64_t>(idx) * kPageSize);
    splitmix_step(st);
    return st;
}

uint64_t fnv1a(const uint8_t* p, size_t n) noexcept {
    uint64_t h = 0xCBF29CE484222325ULL;
    for (size_t i = 0; i < n; ++i) {
        h ^= p[i];
        h *= 0x100000001B3ULL;
    }
    return h;
}

void retire_page_locked(uint64_t page) noexcept {
    DWORD old = 0;
    if (VirtualProtect(reinterpret_cast<void*>(page), kPageSize,
                       PAGE_READWRITE, &old)) {
        std::memset(reinterpret_cast<void*>(page), 0, kPageSize);
        VirtualProtect(reinterpret_cast<void*>(page), kPageSize,
                       PAGE_NOACCESS, &old);
    }
}

bool decrypt_page_locked(uint64_t page) noexcept {
    const uint64_t base64 = reinterpret_cast<uint64_t>(g_base);
    const size_t idx = static_cast<size_t>((page - base64) / kPageSize);
    if (idx >= g_pages) return false;

    uint8_t* src = g_cipher + idx * kPageSize;
    DWORD old = 0;
    if (!VirtualProtect(src, kPageSize, PAGE_READWRITE, &old)) return false;
    if (!VirtualProtect(reinterpret_cast<void*>(page), kPageSize,
                        PAGE_READWRITE, &old)) {
        VirtualProtect(src, kPageSize, PAGE_NOACCESS, &old);
        return false;
    }

    uint8_t* dst = reinterpret_cast<uint8_t*>(page);
    uint64_t st = page_seed(idx);
    for (size_t i = 0; i < kPageSize; ++i) {
        uint8_t ks = static_cast<uint8_t>(splitmix_step(st) & 0xFF);
        dst[i] = src[i] ^ ks;
    }
    VirtualProtect(reinterpret_cast<void*>(page), kPageSize,
                   PAGE_EXECUTE_READ, &old);
    VirtualProtect(src, kPageSize, PAGE_NOACCESS, &old);

    // FIFO window: day cua so, retire trang cu nhat (mu - an toan correctness)
    if (g_window_n == kWindow) {
        retire_page_locked(g_window[0]);
        for (size_t i = 1; i < g_window_n; ++i)
            g_window[i - 1] = g_window[i];
        --g_window_n;
    }
    g_window[g_window_n++] = page;
    return true;
}

LONG CALLBACK veh(PEXCEPTION_POINTERS ex) noexcept {
    if (ex->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION)
        return EXCEPTION_CONTINUE_SEARCH;
    if (!g_installed) return EXCEPTION_CONTINUE_SEARCH;

    const uint64_t fault = static_cast<uint64_t>(
        ex->ExceptionRecord->ExceptionInformation[1]);
    const uint64_t page = fault & ~static_cast<uint64_t>(kPageSize - 1);
    const uint64_t base = reinterpret_cast<uint64_t>(g_base);
    if (page < base || page >= base + g_size) return EXCEPTION_CONTINUE_SEARCH;

    // Chi phuc vu FETCH tai chinh trang fault (RIP cung trang) -> tu choi
    // memcpy/doc data tu code khac (scanner noi bo).
    const uint64_t rip = static_cast<uint64_t>(ex->ContextRecord->Rip);
    if (rip < base || rip >= base + g_size) return EXCEPTION_CONTINUE_SEARCH;
    if ((rip & ~static_cast<uint64_t>(kPageSize - 1)) != page)
        return EXCEPTION_CONTINUE_SEARCH;

    ensure_lock();
    EnterCriticalSection(&g_cs);
    const bool ok = decrypt_page_locked(page);
    LeaveCriticalSection(&g_cs);
    return ok ? EXCEPTION_CONTINUE_EXECUTION : EXCEPTION_CONTINUE_SEARCH;
}

} // namespace

bool install(void* code_base, size_t code_size,
             const uint8_t* cipher, uint64_t master_seed) noexcept {
    if (!code_base || !cipher || code_size == 0) return false;
    const uint64_t base = reinterpret_cast<uint64_t>(code_base);
    if (base & (kPageSize - 1)) return false;

    const size_t pages = (code_size + kPageSize - 1) / kPageSize;
    if (pages == 0 || pages > kMaxPages) return false;

    ensure_lock();
    EnterCriticalSection(&g_cs);

    g_base  = static_cast<uint8_t*>(code_base);
    g_size  = pages * kPageSize;
    g_seed  = master_seed;
    g_pages = pages;
    g_window_n = 0;

    g_cipher = static_cast<uint8_t*>(
        VirtualAlloc(nullptr, pages * kPageSize, MEM_COMMIT | MEM_RESERVE,
                     PAGE_READWRITE));
    if (!g_cipher) { LeaveCriticalSection(&g_cs); return false; }
    std::memcpy(g_cipher, cipher, pages * kPageSize);
    g_hash = fnv1a(g_cipher, pages * kPageSize);

    DWORD old = 0;
    VirtualProtect(g_cipher, pages * kPageSize, PAGE_NOACCESS, &old);
    VirtualProtect(code_base, pages * kPageSize, PAGE_NOACCESS, &old);

    g_veh = AddVectoredExceptionHandler(1, veh);
    InterlockedExchange(&g_installed, 1);

    LeaveCriticalSection(&g_cs);
    return true;
}

void uninstall() noexcept {
    ensure_lock();
    EnterCriticalSection(&g_cs);
    InterlockedExchange(&g_installed, 0);
    if (g_veh) { RemoveVectoredExceptionHandler(g_veh); g_veh = nullptr; }
    if (g_cipher) {
        VirtualFree(g_cipher, 0, MEM_RELEASE);
        g_cipher = nullptr;
    }
    if (g_base && g_size) {
        DWORD old = 0;
        VirtualProtect(g_base, g_size, PAGE_EXECUTE_READ, &old);
    }
    g_base = nullptr;
    g_size = 0;
    g_pages = 0;
    g_window_n = 0;
    LeaveCriticalSection(&g_cs);
}

bool active() noexcept { return g_installed != 0; }

uint64_t cipher_hash() noexcept { return g_hash; }

} // namespace vpack::vault
