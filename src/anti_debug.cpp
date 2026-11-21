#include "vpack/anti_debug.h"
#include "vpack/anti_vm.h"
#include "vpack/anti_dump.h"
#include "vpack/crypto.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <intrin.h>
#include <chrono>

namespace vpack::antidebug {

namespace {

using FnNtQueryInformationProcess = LONG(NTAPI*)(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

using FnNtSetInformationThread = LONG(NTAPI*)(
    HANDLE ThreadHandle,
    ULONG ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength
);

using FnNtQueryInformationThread = LONG(NTAPI*)(
    HANDLE ThreadHandle,
    ULONG ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength
);

thread_local bool g_thread_hidden_requested = false;

using FnNtQuerySystemInformation = LONG(NTAPI*)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

using FnNtCreateThreadEx = LONG(NTAPI*)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

VPACK_FORCEINLINE const uint8_t* get_peb() noexcept {
#if defined(_M_X64) || defined(__x86_64__)
    return reinterpret_cast<const uint8_t*>(__readgsqword(0x60));
#elif defined(_M_IX86) || defined(__i386__)
    return reinterpret_cast<const uint8_t*>(__readfsdword(0x30));
#else
    return nullptr;
#endif
}

LONG call_nt_query_info_process(
    HANDLE proc,
    ULONG info_class,
    PVOID buf,
    ULONG len,
    PULONG ret_len,
    bool* out_hooked = nullptr
) noexcept {
    static antidump::SyscallEntry sc_entry{};
    static bool resolved = false;
    if (!resolved) {
        resolved = antidump::resolve_ntdll_syscall(VPACK_HASH_CI("NtQueryInformationProcess"), sc_entry);
    }
    if (out_hooked && sc_entry.is_hooked) {
        *out_hooked = true;
    }
    if (resolved && sc_entry.gadget_addr && sc_entry.ssn != 0xFFFFFFFFu) {
        return static_cast<LONG>(antidump::invoke_indirect_syscall(
            sc_entry,
            static_cast<uint64_t>(reinterpret_cast<uintptr_t>(proc)),
            static_cast<uint64_t>(info_class),
            reinterpret_cast<uint64_t>(buf),
            static_cast<uint64_t>(len),
            reinterpret_cast<uint64_t>(ret_len)
        ));
    }

    static auto nt_query_proc = VPACK_IMPORT(
        FnNtQueryInformationProcess,
        "ntdll.dll",
        "NtQueryInformationProcess"
    );
    FnNtQueryInformationProcess fn = nt_query_proc.get();
    if (!fn) return -1;
    return fn(proc, info_class, buf, len, ret_len);
}

} // namespace

bool check_peb_being_debugged() noexcept {
    const uint8_t* peb = get_peb();
    if (!peb) return false;
    return peb[0x02] != 0;
}

bool check_nt_global_flag() noexcept {
    const uint8_t* peb = get_peb();
    if (!peb) return false;
#if defined(_M_X64) || defined(__x86_64__)
    const uint32_t nt_global_flag = *reinterpret_cast<const uint32_t*>(peb + 0xBC);
#else
    const uint32_t nt_global_flag = *reinterpret_cast<const uint32_t*>(peb + 0x68);
#endif
    return (nt_global_flag & 0x70u) == 0x70u;
}

bool check_heap_flags() noexcept {
    const uint8_t* peb = get_peb();
    if (!peb) return false;
#if defined(_M_X64) || defined(__x86_64__)
    const auto* process_heap = *reinterpret_cast<const uint8_t* const*>(peb + 0x30);
    if (!process_heap) return false;
    const uint32_t flags       = *reinterpret_cast<const uint32_t*>(process_heap + 0x70);
    const uint32_t force_flags = *reinterpret_cast<const uint32_t*>(process_heap + 0x74);
#else
    const auto* process_heap = *reinterpret_cast<const uint8_t* const*>(peb + 0x18);
    if (!process_heap) return false;
    const uint32_t flags       = *reinterpret_cast<const uint32_t*>(process_heap + 0x40);
    const uint32_t force_flags = *reinterpret_cast<const uint32_t*>(process_heap + 0x44);
#endif
    // HEAP_TAIL_CHECKING_ENABLED (0x20) | HEAP_FREE_CHECKING_ENABLED (0x40) | HEAP_VALIDATE_PARAMETERS_ENABLED (0x40000000)
    return (flags & 0x40000060u) != 0u || force_flags != 0u;
}

bool check_parent_debugger() noexcept {
    static volatile LONG s_cache_state = 0; // 0 = uninit, 1 = clean, 2 = debugger parent
    const LONG cached = InterlockedCompareExchange(&s_cache_state, 0, 0);
    if (cached != 0) {
        return cached == 2;
    }

    struct ProcessBasicInfoLocal {
        uintptr_t ExitStatus;
        uintptr_t PebBaseAddress;
        uintptr_t AffinityMask;
        uintptr_t BasePriority;
        uintptr_t UniqueProcessId;
        uintptr_t InheritedFromUniqueProcessId;
    } pbi{};

    ULONG ret_len = 0;
    if (call_nt_query_info_process(GetCurrentProcess(), 0, &pbi, sizeof(pbi), &ret_len) != 0 ||
        pbi.InheritedFromUniqueProcessId == 0) {
        InterlockedExchange(&s_cache_state, 1);
        return false;
    }

    bool is_dbg_parent = false;

    using FnOpenProcess = HANDLE(WINAPI*)(DWORD, BOOL, DWORD);
    using FnQueryNameA   = BOOL(WINAPI*)(HANDLE, DWORD, LPSTR, PDWORD);
    using FnCloseHandle  = BOOL(WINAPI*)(HANDLE);
    static auto fn_open  = VPACK_IMPORT(FnOpenProcess, "kernel32.dll", "OpenProcess");
    static auto fn_qname = VPACK_IMPORT(FnQueryNameA, "kernel32.dll", "QueryFullProcessImageNameA");
    static auto fn_close = VPACK_IMPORT(FnCloseHandle, "kernel32.dll", "CloseHandle");

    if (fn_open.get() && fn_qname.get()) {
        constexpr DWORD kQueryLimitedInfo = 0x1000u; // PROCESS_QUERY_LIMITED_INFORMATION
        HANDLE parent = fn_open(
            kQueryLimitedInfo,
            FALSE,
            static_cast<DWORD>(pbi.InheritedFromUniqueProcessId)
        );
        if (parent) {
            char path[MAX_PATH * 2]{};
            DWORD name_size = static_cast<DWORD>(sizeof(path));
            if (fn_qname(parent, 0, path, &name_size)) {
                const char* base_name = path;
                for (const char* p = path; *p; ++p) {
                    if (*p == '\\' || *p == '/') {
                        base_name = p + 1;
                    }
                }
                const uint64_t parent_hash = crypto::fnv1a_64_ci(base_name);
                constexpr uint64_t kDebuggerHashes[] = {
                    VPACK_HASH_CI("x64dbg.exe"),
                    VPACK_HASH_CI("x32dbg.exe"),
                    VPACK_HASH_CI("x96dbg.exe"),
                    VPACK_HASH_CI("ida.exe"),
                    VPACK_HASH_CI("ida64.exe"),
                    VPACK_HASH_CI("idag.exe"),
                    VPACK_HASH_CI("idag64.exe"),
                    VPACK_HASH_CI("idaq.exe"),
                    VPACK_HASH_CI("idaq64.exe"),
                    VPACK_HASH_CI("windbg.exe"),
                    VPACK_HASH_CI("windbgx.exe"),
                    VPACK_HASH_CI("ollydbg.exe"),
                    VPACK_HASH_CI("ollyice.exe"),
                    VPACK_HASH_CI("radare2.exe"),
                    VPACK_HASH_CI("r2.exe"),
                    VPACK_HASH_CI("rabin2.exe"),
                    VPACK_HASH_CI("cutter.exe"),
                    VPACK_HASH_CI("ghidra.exe"),
                    VPACK_HASH_CI("cheatengine-x86_64.exe"),
                    VPACK_HASH_CI("cheatengine-x86_64-sse4-avx2.exe"),
                    VPACK_HASH_CI("hyperdbg-cli.exe"),
                    VPACK_HASH_CI("dbg64.exe")
                };
                for (uint64_t dh : kDebuggerHashes) {
                    if (parent_hash == dh) {
                        is_dbg_parent = true;
                        break;
                    }
                }
            }
            crypto::secure_wipe(path, sizeof(path), pbi.InheritedFromUniqueProcessId);
            if (fn_close.get()) {
                fn_close(parent);
            }
        }
    }

    InterlockedExchange(&s_cache_state, is_dbg_parent ? 2 : 1);
    return is_dbg_parent;
}

bool verify_thread_hidden() noexcept {
    if (!g_thread_hidden_requested) {
        return true;
    }

    static antidump::SyscallEntry sc_qthread{};
    static bool resolved = false;
    if (!resolved) {
        resolved = antidump::resolve_ntdll_syscall(VPACK_HASH_CI("NtQueryInformationThread"), sc_qthread);
    }

    BOOLEAN is_hidden = 1;
    ULONG   ret_len   = 0;
    LONG    status    = -1;

    if (resolved && sc_qthread.gadget_addr && sc_qthread.ssn != 0xFFFFFFFFu) {
        status = static_cast<LONG>(antidump::invoke_indirect_syscall(
            sc_qthread,
            static_cast<uint64_t>(reinterpret_cast<uintptr_t>(GetCurrentThread())),
            0x11ULL, // ThreadHideFromDebugger
            reinterpret_cast<uint64_t>(&is_hidden),
            sizeof(BOOLEAN),
            reinterpret_cast<uint64_t>(&ret_len)
        ));
    } else {
        static auto nt_qthread = VPACK_IMPORT(FnNtQueryInformationThread, "ntdll.dll", "NtQueryInformationThread");
        if (nt_qthread.get()) {
            status = nt_qthread(GetCurrentThread(), 0x11u, &is_hidden, sizeof(BOOLEAN), &ret_len);
        }
    }

    if (status == 0 && is_hidden == 0) {
        return false; // ScyllaHide / TitanHide suppressed ThreadHideFromDebugger!
    }
    return true;
}

bool check_kuser_shared_data() noexcept {
    // KUSER_SHARED_DATA at fixed address 0x7FFE0000 on all x64 Windows kernels:
    // +0x2D4: BOOLEAN KdDebuggerEnabled (bit 0 = enabled, bit 1 = not present)
    const volatile uint8_t* kd_enabled = reinterpret_cast<const volatile uint8_t*>(0x7FFE02D4ULL);
    uint8_t val = *kd_enabled;
    return (val & 0x01u) != 0 || (val & 0x03u) == 0x03u;
}

uint32_t check_nt_query_debug() noexcept {
    uint32_t flags = THREAT_NONE;
    HANDLE self = GetCurrentProcess();
    bool hooked = false;

    // 1. ProcessDebugPort (0x07) via Indirect Syscall (bypasses ScyllaHide inline hooks)
    uintptr_t debug_port = 0;
    LONG status = call_nt_query_info_process(self, 0x07, &debug_port, sizeof(debug_port), nullptr, &hooked);
    if (status == 0 && debug_port != 0) {
        flags |= THREAT_DEBUG_PORT;
    }

    // 2. ProcessDebugObjectHandle (0x1E) via Indirect Syscall
    HANDLE debug_object = nullptr;
    status = call_nt_query_info_process(self, 0x1E, &debug_object, sizeof(debug_object), nullptr, &hooked);
    if (status == 0 && debug_object != nullptr) {
        flags |= THREAT_DEBUG_OBJECT_HANDLE;
    }

    // 3. ProcessDebugFlags (0x1F) - NoDebugInherit == 0 means debugger attached
    ULONG debug_flags = 1;
    status = call_nt_query_info_process(self, 0x1F, &debug_flags, sizeof(debug_flags), nullptr, &hooked);
    if (status == 0 && debug_flags == 0) {
        flags |= THREAT_DEBUG_FLAGS;
    }

    if (hooked || antidump::detect_ntdll_inline_hooks()) {
        flags |= THREAT_NTDLL_HOOKED;
    }

    return flags;
}

bool check_kernel_debugger() noexcept {
    if (check_kuser_shared_data()) {
        return true;
    }

    static antidump::SyscallEntry sc_sys{};
    static bool resolved = false;
    if (!resolved) {
        resolved = antidump::resolve_ntdll_syscall(VPACK_HASH_CI("NtQuerySystemInformation"), sc_sys);
    }

    struct SystemKernelDebuggerInfo {
        BOOLEAN KernelDebuggerEnabled;
        BOOLEAN KernelDebuggerNotPresent;
    } info{0, 1};

    LONG status = -1;
    if (resolved && sc_sys.gadget_addr && sc_sys.ssn != 0xFFFFFFFFu) {
        status = static_cast<LONG>(antidump::invoke_indirect_syscall(
            sc_sys,
            0x23ULL,
            reinterpret_cast<uint64_t>(&info),
            sizeof(info),
            0ULL
        ));
    } else {
        static auto nt_query_sys = VPACK_IMPORT(
            FnNtQuerySystemInformation,
            "ntdll.dll",
            "NtQuerySystemInformation"
        );
        if (nt_query_sys.get()) {
            status = nt_query_sys(0x23, &info, static_cast<ULONG>(sizeof(info)), nullptr);
        }
    }

    if (status == 0) {
        if (info.KernelDebuggerEnabled || !info.KernelDebuggerNotPresent) {
            return true;
        }
    }
    return false;
}

bool check_and_clear_hardware_breakpoints(bool clear_if_found, uint32_t* out_count) noexcept {
    static antidump::SyscallEntry sc_get_ctx{};
    static antidump::SyscallEntry sc_set_ctx{};
    static bool sc_resolved = false;
    if (!sc_resolved) {
        antidump::resolve_ntdll_syscall(VPACK_HASH_CI("NtGetContextThread"), sc_get_ctx);
        antidump::resolve_ntdll_syscall(VPACK_HASH_CI("NtSetContextThread"), sc_set_ctx);
        sc_resolved = true;
    }

    alignas(16) CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    HANDLE thread = GetCurrentThread();
    bool got_ctx = false;

    // 1. Primary path: Indirect Syscall to NtGetContextThread (bypasses ScyllaHide hook)
    if (sc_get_ctx.gadget_addr && sc_get_ctx.ssn != 0xFFFFFFFFu) {
        LONG status = static_cast<LONG>(antidump::invoke_indirect_syscall(
            sc_get_ctx,
            static_cast<uint64_t>(reinterpret_cast<uintptr_t>(thread)),
            reinterpret_cast<uint64_t>(&ctx)
        ));
        got_ctx = (status == 0);
    }

    // 2. Fallback if Indirect Syscall unavailable
    if (!got_ctx) {
        using FnGetThreadContext = BOOL(WINAPI*)(HANDLE, LPCONTEXT);
        static auto fn_get_ctx = VPACK_IMPORT(FnGetThreadContext, "kernel32.dll", "GetThreadContext");
        if (!fn_get_ctx.get() || !fn_get_ctx(thread, &ctx)) {
            if (out_count) *out_count = 0;
            return false;
        }
    }

    uint32_t count = 0;
    if (ctx.Dr0 != 0) ++count;
    if (ctx.Dr1 != 0) ++count;
    if (ctx.Dr2 != 0) ++count;
    if (ctx.Dr3 != 0) ++count;
    if ((ctx.Dr7 & 0xFFu) != 0) ++count;

    if (out_count) *out_count = count;

    if (count > 0 && clear_if_found) {
        ctx.Dr0 = 0;
        ctx.Dr1 = 0;
        ctx.Dr2 = 0;
        ctx.Dr3 = 0;
        ctx.Dr6 = 0;
        ctx.Dr7 = 0;

        bool set_ok = false;
        if (sc_set_ctx.gadget_addr && sc_set_ctx.ssn != 0xFFFFFFFFu) {
            LONG status = static_cast<LONG>(antidump::invoke_indirect_syscall(
                sc_set_ctx,
                static_cast<uint64_t>(reinterpret_cast<uintptr_t>(thread)),
                reinterpret_cast<uint64_t>(&ctx)
            ));
            set_ok = (status == 0);
        }
        if (!set_ok) {
            using FnSetThreadContext = BOOL(WINAPI*)(HANDLE, const CONTEXT*);
            static auto fn_set_ctx = VPACK_IMPORT(FnSetThreadContext, "kernel32.dll", "SetThreadContext");
            if (fn_set_ctx.get()) {
                fn_set_ctx(thread, &ctx);
            }
        }
    }

    return count > 0;
}

bool check_timing_anomaly(uint64_t threshold_cycles, uint64_t* out_delta) noexcept {
    // Correlate both CPU RDTSC and KUSER_SHARED_DATA InterruptTime (0x7FFE0008, 100ns units)
    const volatile uint64_t* kuser_time = reinterpret_cast<const volatile uint64_t*>(0x7FFE0008ULL);
    uint64_t kt1 = *kuser_time;
    uint64_t t1  = __rdtsc();

    volatile uint64_t acc = 0xE791C3A58B2D4F19ULL;
    for (int i = 0; i < 64; ++i) {
        acc = crypto::mba_xor(acc, static_cast<uint64_t>(i)) * 0x100000001B3ULL;
    }
    (void)acc;

    uint64_t t2  = __rdtsc();
    uint64_t kt2 = *kuser_time;

    uint64_t delta   = (t2 > t1) ? (t2 - t1) : 0;
    uint64_t k_delta = (kt2 > kt1) ? (kt2 - kt1) : 0; // > 500000 (~50ms) means single-stepping!
    if (out_delta) *out_delta = delta;
    return (delta > threshold_cycles) || (k_delta > 500000ULL);
}

bool scan_software_breakpoints(const void* address, size_t size) noexcept {
    if (!address || size == 0) return false;
    const auto* bytes = static_cast<const uint8_t*>(address);
    if (bytes[0] == 0xCC) {
        return true;
    }
    if (size >= 2 && bytes[0] == 0xCD && bytes[1] == 0x03) {
        return true;
    }
    for (size_t i = 0; i < size; ++i) {
        if (bytes[i] == 0xCC) {
            return true;
        }
    }
    return false;
}

uint64_t compute_environmental_key_poison() noexcept {
    uint64_t poison = 0;
    const uint8_t* peb = get_peb();
    if (peb) {
        // Branchless extraction of BeingDebugged and NtGlobalFlag
        uint64_t bd  = static_cast<uint64_t>(peb[0x02]);
#if defined(_M_X64) || defined(__x86_64__)
        uint64_t ngf = static_cast<uint64_t>(*reinterpret_cast<const uint32_t*>(peb + 0xBC) & 0x70u);
#else
        uint64_t ngf = static_cast<uint64_t>(*reinterpret_cast<const uint32_t*>(peb + 0x68) & 0x70u);
#endif
        poison = crypto::mba_add(bd * 0x9E3779B97F4A7C15ULL, ngf * 0xBF58476D1CE4E5B9ULL);
    }

    // Mix KUSER_SHARED_DATA->KdDebuggerEnabled bit 0
    const volatile uint8_t* kd = reinterpret_cast<const volatile uint8_t*>(0x7FFE02D4ULL);
    poison ^= static_cast<uint64_t>(*kd & 0x01u) * 0x94D049BB133111EBULL;

    // Mix ProcessDebugPort via Indirect Syscall
    uintptr_t debug_port = 0;
    bool hooked = false;
    if (call_nt_query_info_process(GetCurrentProcess(), 0x07, &debug_port, sizeof(debug_port), nullptr, &hooked) == 0) {
        poison = crypto::mba_xor(poison, static_cast<uint64_t>(debug_port) * 0xD8B39A17E4C28F95ULL);
    }
    if (hooked) {
        poison ^= 0xDEAD10CCBAD0F00DULL;
    }
    if (!antidump::verify_vcode_integrity()) {
        poison ^= 0xC0DEC0FFEEBADBEEULL;
    }
    if (check_heap_flags()) {
        poison ^= 0x7E4AF1A65BADF00DULL;
    }
    if (check_parent_debugger()) {
        poison ^= 0x9A8B7C6D5E4F3A21ULL;
    }
    if (!verify_thread_hidden()) {
        poison ^= 0xF00DBABE1337CAFEULL;
    }

    // Mix branchless Anti-VM / Hypervisor poison (0ULL on physical hardware & VBS Root Partition)
    poison = crypto::mba_xor(poison, antivm::compute_vm_key_poison());

    return poison;
}

bool hide_current_thread() noexcept {
    static antidump::SyscallEntry sc_hide{};
    static bool resolved = false;
    if (!resolved) {
        resolved = antidump::resolve_ntdll_syscall(VPACK_HASH_CI("NtSetInformationThread"), sc_hide);
    }

    // ThreadHideFromDebugger = 0x11 via Indirect Syscall
    if (resolved && sc_hide.gadget_addr && sc_hide.ssn != 0xFFFFFFFFu) {
        LONG status = static_cast<LONG>(antidump::invoke_indirect_syscall(
            sc_hide,
            static_cast<uint64_t>(reinterpret_cast<uintptr_t>(GetCurrentThread())),
            0x11ULL,
            0ULL,
            0ULL
        ));
        if (status == 0) {
            g_thread_hidden_requested = true;
            return true;
        }
    }

    static auto nt_set_thread = VPACK_IMPORT(
        FnNtSetInformationThread,
        "ntdll.dll",
        "NtSetInformationThread"
    );

    FnNtSetInformationThread fn = nt_set_thread.get();
    if (!fn) return false;

    LONG status = fn(GetCurrentThread(), 0x11, nullptr, 0);
    if (status == 0) {
        g_thread_hidden_requested = true;
        return true;
    }
    return false;
}

namespace {

struct HiddenThreadCtx {
    std::function<void()> task;
};

unsigned long __stdcall hidden_thread_entry(void* param) noexcept {
    hide_current_thread();
    auto* ctx = static_cast<HiddenThreadCtx*>(param);
    if (ctx) {
        if (ctx->task) {
            ctx->task();
        }
        delete ctx;
    }
    return 0;
}

} // namespace

void* spawn_hidden_thread(std::function<void()> task) noexcept {
    static antidump::SyscallEntry sc_create_thread{};
    static bool sc_resolved = false;
    if (!sc_resolved) {
        sc_resolved = antidump::resolve_ntdll_syscall(VPACK_HASH_CI("NtCreateThreadEx"), sc_create_thread);
    }

    auto* ctx = new (std::nothrow) HiddenThreadCtx{std::move(task)};
    if (!ctx) return nullptr;

    constexpr ULONG kThreadCreateHideFromDebugger = 0x00000004u;
    HANDLE hThread = nullptr;
    LONG   status  = -1;

    // 1. Primary path: Indirect Syscall to NtCreateThreadEx with THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER (0x04)
    if (sc_resolved && sc_create_thread.gadget_addr && sc_create_thread.ssn != 0xFFFFFFFFu) {
        status = static_cast<LONG>(antidump::invoke_indirect_syscall(
            sc_create_thread,
            reinterpret_cast<uint64_t>(&hThread),
            static_cast<uint64_t>(THREAD_ALL_ACCESS),
            0ULL,
            static_cast<uint64_t>(reinterpret_cast<uintptr_t>(GetCurrentProcess())),
            reinterpret_cast<uint64_t>(&hidden_thread_entry),
            reinterpret_cast<uint64_t>(ctx),
            static_cast<uint64_t>(kThreadCreateHideFromDebugger),
            0ULL,
            0x10000ULL,
            0x100000ULL,
            0ULL
        ));
    }

    // 2. Fallback to imported NtCreateThreadEx if needed
    if (status != 0 || !hThread) {
        static auto nt_create_thread = VPACK_IMPORT(
            FnNtCreateThreadEx,
            "ntdll.dll",
            "NtCreateThreadEx"
        );
        FnNtCreateThreadEx fn = nt_create_thread.get();
        if (fn) {
            status = fn(
                &hThread,
                THREAD_ALL_ACCESS,
                nullptr,
                GetCurrentProcess(),
                reinterpret_cast<PVOID>(&hidden_thread_entry),
                ctx,
                kThreadCreateHideFromDebugger,
                0,
                0x10000,
                0x100000,
                nullptr
            );
        }
    }

    if (status != 0 || !hThread) {
        delete ctx;
        return nullptr;
    }
    return hThread;
}

void join_hidden_thread(void* thread_handle, uint32_t timeout_ms) noexcept {
    if (!thread_handle) return;
    using FnWaitForSingleObject = DWORD(WINAPI*)(HANDLE, DWORD);
    using FnCloseHandle         = BOOL(WINAPI*)(HANDLE);
    static auto fn_wait  = VPACK_IMPORT(FnWaitForSingleObject, "kernel32.dll", "WaitForSingleObject");
    static auto fn_close = VPACK_IMPORT(FnCloseHandle, "kernel32.dll", "CloseHandle");
    if (fn_wait.get())  fn_wait(static_cast<HANDLE>(thread_handle), timeout_ms);
    if (fn_close.get()) fn_close(static_cast<HANDLE>(thread_handle));
}

DebugReport run_all_checks(bool clear_hwbp) noexcept {
    DebugReport report{};

    if (check_peb_being_debugged()) {
        report.flags |= THREAT_PEB_BEING_DEBUGGED;
    }
    if (check_nt_global_flag()) {
        report.flags |= THREAT_NT_GLOBAL_FLAG;
    }
    if (check_heap_flags()) {
        report.flags |= THREAT_HEAP_FLAGS;
    }
    if (check_parent_debugger()) {
        report.flags |= THREAT_PARENT_DEBUGGER;
    }
    if (!verify_thread_hidden()) {
        report.flags |= THREAT_THREAD_HIDE_BYPASS;
    }

    report.flags |= check_nt_query_debug();

    if (check_kuser_shared_data()) {
        report.flags |= THREAT_KUSER_DEBUGGER;
    }

    if (check_kernel_debugger()) {
        report.flags |= THREAT_KERNEL_DEBUGGER;
    }

    uint32_t hwbp_count = 0;
    if (check_and_clear_hardware_breakpoints(clear_hwbp, &hwbp_count)) {
        report.flags |= THREAT_HARDWARE_BREAKPOINT;
        report.cleared_hwbp_count = hwbp_count;
    }

    uint64_t delta = 0;
    if (check_timing_anomaly(500000ULL, &delta)) {
        report.flags |= THREAT_TIMING_ANOMALY;
    }
    report.rdtsc_delta = delta;

    if (!antidump::verify_vcode_integrity()) {
        report.flags |= THREAT_VCODE_TAMPERED;
    }

    if (antivm::is_running_in_vm(nullptr)) {
        report.flags |= THREAT_VIRTUAL_MACHINE;
    }

    return report;
}

Watchdog::~Watchdog() {
    stop();
}

unsigned long __stdcall Watchdog::thread_proc(void* param) noexcept {
    auto* self = static_cast<Watchdog*>(param);
    hide_current_thread();

    using FnSleep = VOID(WINAPI*)(DWORD);
    static auto fn_sleep = VPACK_IMPORT(FnSleep, "kernel32.dll", "Sleep");

    while (self->running_.load(std::memory_order_acquire)) {
        antidump::rotate_vcode_idle_key();
        DebugReport rep = run_all_checks(true);
        if (rep.detected() && self->callback_) {
            self->callback_(rep);
        }
        if (fn_sleep.get()) {
            fn_sleep(self->interval_ms_);
        }
    }
    return 0;
}

void Watchdog::start(uint32_t interval_ms, Callback on_detect) {
    bool expected = false;
    if (!running_.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        return;
    }

    interval_ms_   = interval_ms;
    callback_      = std::move(on_detect);
    thread_handle_ = spawn_hidden_thread([this]() { Watchdog::thread_proc(this); });
}

void Watchdog::stop() {
    if (running_.exchange(false, std::memory_order_acq_rel)) {
        if (thread_handle_) {
            join_hidden_thread(thread_handle_, 5000);
            thread_handle_ = nullptr;
        }
    }
}

} // namespace vpack::antidebug
