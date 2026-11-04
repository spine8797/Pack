#include "vpack/anti_debug.h"
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

uint32_t check_nt_query_debug() noexcept {
    uint32_t flags = THREAT_NONE;

    static auto nt_query_proc = VPACK_IMPORT(
        FnNtQueryInformationProcess,
        "ntdll.dll",
        "NtQueryInformationProcess"
    );

    FnNtQueryInformationProcess fn = nt_query_proc.get();
    if (!fn) return flags;

    HANDLE self = GetCurrentProcess();

    // 1. ProcessDebugPort (0x07)
    uintptr_t debug_port = 0;
    LONG status = fn(self, 0x07, &debug_port, sizeof(debug_port), nullptr);
    if (status == 0 && debug_port != 0) {
        flags |= THREAT_DEBUG_PORT;
    }

    // 2. ProcessDebugObjectHandle (0x1E)
    HANDLE debug_object = nullptr;
    status = fn(self, 0x1E, &debug_object, sizeof(debug_object), nullptr);
    if (status == 0 && debug_object != nullptr) {
        flags |= THREAT_DEBUG_OBJECT_HANDLE;
    }

    // 3. ProcessDebugFlags (0x1F) - NoDebugInherit == 0 means debugger attached
    ULONG debug_flags = 1;
    status = fn(self, 0x1F, &debug_flags, sizeof(debug_flags), nullptr);
    if (status == 0 && debug_flags == 0) {
        flags |= THREAT_DEBUG_FLAGS;
    }

    return flags;
}

bool check_kernel_debugger() noexcept {
    static auto nt_query_sys = VPACK_IMPORT(
        FnNtQuerySystemInformation,
        "ntdll.dll",
        "NtQuerySystemInformation"
    );

    FnNtQuerySystemInformation fn = nt_query_sys.get();
    if (!fn) return false;

    struct SystemKernelDebuggerInfo {
        BOOLEAN KernelDebuggerEnabled;
        BOOLEAN KernelDebuggerNotPresent;
    } info{0, 1};

    // SystemKernelDebuggerInformation = 0x23
    LONG status = fn(0x23, &info, sizeof(info), nullptr);
    if (status == 0) {
        if (info.KernelDebuggerEnabled || !info.KernelDebuggerNotPresent) {
            return true;
        }
    }
    return false;
}

bool check_and_clear_hardware_breakpoints(bool clear_if_found, uint32_t* out_count) noexcept {
    using FnGetThreadContext = BOOL(WINAPI*)(HANDLE, LPCONTEXT);
    using FnSetThreadContext = BOOL(WINAPI*)(HANDLE, const CONTEXT*);

    static auto fn_get_ctx = VPACK_IMPORT(FnGetThreadContext, "kernel32.dll", "GetThreadContext");
    static auto fn_set_ctx = VPACK_IMPORT(FnSetThreadContext, "kernel32.dll", "SetThreadContext");

    if (!fn_get_ctx.get()) {
        if (out_count) *out_count = 0;
        return false;
    }

    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    HANDLE thread = GetCurrentThread();
    if (!fn_get_ctx(thread, &ctx)) {
        if (out_count) *out_count = 0;
        return false;
    }

    uint32_t count = 0;
    if (ctx.Dr0 != 0) ++count;
    if (ctx.Dr1 != 0) ++count;
    if (ctx.Dr2 != 0) ++count;
    if (ctx.Dr3 != 0) ++count;
    if ((ctx.Dr7 & 0xFFu) != 0) ++count;

    if (out_count) *out_count = count;

    if (count > 0 && clear_if_found && fn_set_ctx.get()) {
        ctx.Dr0 = 0;
        ctx.Dr1 = 0;
        ctx.Dr2 = 0;
        ctx.Dr3 = 0;
        ctx.Dr6 = 0;
        ctx.Dr7 = 0;
        fn_set_ctx(thread, &ctx);
    }

    return count > 0;
}

bool check_timing_anomaly(uint64_t threshold_cycles, uint64_t* out_delta) noexcept {
    uint64_t t1 = __rdtsc();

    volatile uint64_t acc = 0x5341424C45ULL;
    for (int i = 0; i < 64; ++i) {
        acc = (acc ^ static_cast<uint64_t>(i)) * 0x100000001B3ULL;
    }
    (void)acc;

    uint64_t t2 = __rdtsc();
    uint64_t delta = (t2 > t1) ? (t2 - t1) : 0;
    if (out_delta) *out_delta = delta;
    return delta > threshold_cycles;
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

bool hide_current_thread() noexcept {
    static auto nt_set_thread = VPACK_IMPORT(
        FnNtSetInformationThread,
        "ntdll.dll",
        "NtSetInformationThread"
    );

    FnNtSetInformationThread fn = nt_set_thread.get();
    if (!fn) return false;

    // ThreadHideFromDebugger = 0x11
    LONG status = fn(GetCurrentThread(), 0x11, nullptr, 0);
    return status == 0;
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
    static auto nt_create_thread = VPACK_IMPORT(
        FnNtCreateThreadEx,
        "ntdll.dll",
        "NtCreateThreadEx"
    );

    FnNtCreateThreadEx fn = nt_create_thread.get();
    if (!fn) return nullptr;

    auto* ctx = new (std::nothrow) HiddenThreadCtx{std::move(task)};
    if (!ctx) return nullptr;

    HANDLE hThread = nullptr;
    LONG status = fn(
        &hThread,
        THREAD_ALL_ACCESS,
        nullptr,
        GetCurrentProcess(),
        reinterpret_cast<PVOID>(&hidden_thread_entry),
        ctx,
        0,
        0,
        0x10000,
        0x100000,
        nullptr
    );

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

    report.flags |= check_nt_query_debug();

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
