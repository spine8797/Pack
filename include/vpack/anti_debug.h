#pragma once

#include "vpack/config.h"
#include <cstdint>
#include <cstddef>
#include <atomic>
#include <functional>

namespace vpack::antidebug {

enum ThreatFlag : uint32_t {
    THREAT_NONE                 = 0,
    THREAT_PEB_BEING_DEBUGGED   = 1u << 0,
    THREAT_NT_GLOBAL_FLAG       = 1u << 1,
    THREAT_DEBUG_PORT           = 1u << 2,
    THREAT_DEBUG_OBJECT_HANDLE  = 1u << 3,
    THREAT_DEBUG_FLAGS          = 1u << 4,
    THREAT_HARDWARE_BREAKPOINT  = 1u << 5,
    THREAT_TIMING_ANOMALY       = 1u << 6,
    THREAT_SOFTWARE_BREAKPOINT  = 1u << 7,
    THREAT_KERNEL_DEBUGGER      = 1u << 8,
    THREAT_DLL_INJECTED         = 1u << 9
};

struct DebugReport {
    uint32_t flags = THREAT_NONE;
    uint64_t rdtsc_delta = 0;
    uint32_t cleared_hwbp_count = 0;
    void*    injected_module_base = nullptr;
    char     injected_module_name[64]{};

    bool detected() const noexcept { return flags != THREAT_NONE; }
};

bool check_peb_being_debugged() noexcept;
bool check_nt_global_flag() noexcept;
uint32_t check_nt_query_debug() noexcept;
bool check_kernel_debugger() noexcept;
bool check_and_clear_hardware_breakpoints(bool clear_if_found, uint32_t* out_count = nullptr) noexcept;
bool check_timing_anomaly(uint64_t threshold_cycles = 250000ULL, uint64_t* out_delta = nullptr) noexcept;
bool scan_software_breakpoints(const void* address, size_t size) noexcept;

bool hide_current_thread() noexcept;

void* spawn_hidden_thread(std::function<void()> task) noexcept;
void  join_hidden_thread(void* thread_handle, uint32_t timeout_ms = 5000) noexcept;

DebugReport run_all_checks(bool clear_hwbp = true) noexcept;

class Watchdog {
public:
    using Callback = std::function<void(const DebugReport&)>;

    Watchdog() = default;
    ~Watchdog();

    Watchdog(const Watchdog&) = delete;
    Watchdog& operator=(const Watchdog&) = delete;

    void start(uint32_t interval_ms = 250, Callback on_detect = nullptr);
    void stop();
    bool is_running() const noexcept { return running_.load(std::memory_order_acquire); }

private:
    static unsigned long __stdcall thread_proc(void* param) noexcept;

    std::atomic<bool> running_{false};
    void*             thread_handle_ = nullptr;
    uint32_t          interval_ms_ = 250;
    Callback          callback_;
};

} // namespace vpack::antidebug
