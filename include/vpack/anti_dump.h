#pragma once

#include "vpack/config.h"
#include "vpack/crypto.h"
#include <cstdint>
#include <cstddef>
#include <utility>
#include <functional>

namespace vpack::antidump {

struct ModuleLayoutInfo {
    void*       base_address = nullptr;
    uint32_t    original_size_of_image = 0;
    const void* text_section_base = nullptr;
    size_t      text_section_size = 0;
    uint64_t    text_section_hash = 0;
};

struct SyscallEntry {
    uint32_t    ssn = 0xFFFFFFFFu;
    const void* gadget_addr = nullptr; // Points to `0F 05 C3` (syscall; ret) inside ntdll.dll
    bool        is_hooked = false;
};

bool query_module_layout(void* module_base, ModuleLayoutInfo& out_info) noexcept;

bool erase_pe_headers(void* module_base = nullptr) noexcept;

bool tamper_peb_image_size(uint32_t fake_size_delta = 0x01000000u) noexcept;

uint64_t compute_text_integrity(void* module_base = nullptr) noexcept;
bool verify_text_integrity(uint64_t expected_hash, void* module_base = nullptr) noexcept;

uint32_t capture_module_baseline() noexcept;
bool detect_injected_module(void** out_base = nullptr, char* out_name = nullptr, size_t max_len = 0) noexcept;

void* resolve_export_by_hash(uint64_t module_hash_ci, uint64_t proc_hash_ci) noexcept;

// Resolves SSN via HalosGate / Tartarus' Gate neighbor inspection and locates an
// unhooked `syscall; ret` gadget inside ntdll.dll for Indirect Syscall execution.
bool resolve_ntdll_syscall(uint64_t proc_hash_ci, SyscallEntry& out_entry) noexcept;

long invoke_indirect_syscall(
    const SyscallEntry& entry,
    uint64_t arg1 = 0,
    uint64_t arg2 = 0,
    uint64_t arg3 = 0,
    uint64_t arg4 = 0,
    uint64_t arg5 = 0,
    uint64_t arg6 = 0
) noexcept;

bool detect_ntdll_inline_hooks() noexcept;

// ============================================================================
// JIT Execute & Wipe Engine for .vcode (.sbl1) Protected Functions
// Keeps .vcode encrypted (PAGE_READONLY) in RAM at rest. Decrypts to RX only
// during active function execution and re-encrypts with a mutated rolling key
// immediately upon return.
// ============================================================================
bool init_jit_vcode_vault(
    uint8_t* vcode_base,
    size_t   vcode_size,
    uint64_t boot_key,
    bool     already_encrypted_by_stub
) noexcept;

bool verify_vcode_integrity() noexcept;
bool rotate_vcode_idle_key() noexcept;
uint64_t vcode_jit_generation() noexcept;
bool is_vcode_jit_active() noexcept;

bool modify_vcode_in_vault(const std::function<bool(uint8_t* vcode_base, size_t vcode_size)>& mutator) noexcept;

bool wipe_and_lock_vinit_section(uint8_t* vinit_base, size_t vinit_size) noexcept;

class JitSectionGuard {
public:
    JitSectionGuard() noexcept;
    ~JitSectionGuard() noexcept;

    JitSectionGuard(const JitSectionGuard&) = delete;
    JitSectionGuard& operator=(const JitSectionGuard&) = delete;

    bool is_tampered() const noexcept { return tampered_; }

private:
    bool tampered_ = false;
};

template <typename Fn, typename... Args>
VPACK_FORCEINLINE decltype(auto) jit_invoke(Fn&& fn, Args&&... args) {
    JitSectionGuard guard;
    return static_cast<Fn&&>(fn)( static_cast<Args&&>(args)... );
}

template <typename FnPtr>
class HiddenImport {
public:
    constexpr HiddenImport(uint64_t mod_hash, uint64_t fn_hash) noexcept
        : mod_hash_(mod_hash), fn_hash_(fn_hash), encoded_ptr_(0) {}

    FnPtr get() noexcept {
        constexpr uint64_t kMask = 0xD6E8FEB86659FD93ULL;
        if (encoded_ptr_ == 0) {
            void* raw = resolve_export_by_hash(mod_hash_, fn_hash_);
            encoded_ptr_ = reinterpret_cast<uintptr_t>(raw) ^ static_cast<uintptr_t>(mod_hash_ ^ fn_hash_ ^ kMask);
        }
        uintptr_t decoded = encoded_ptr_ ^ static_cast<uintptr_t>(mod_hash_ ^ fn_hash_ ^ kMask);
        return reinterpret_cast<FnPtr>(decoded);
    }

    template <typename... Args>
    auto operator()(Args&&... args) {
        return get()(static_cast<Args&&>(args)...);
    }

private:
    uint64_t  mod_hash_;
    uint64_t  fn_hash_;
    uintptr_t encoded_ptr_;
};

} // namespace vpack::antidump

#define VPACK_IMPORT(FuncType, DllNameLiteral, FuncNameLiteral) \
    (::vpack::antidump::HiddenImport<FuncType>(VPACK_HASH_CI(DllNameLiteral), VPACK_HASH_CI(FuncNameLiteral)))

#define VPACK_JIT_CALL(Fn, ...) \
    (::vpack::antidump::jit_invoke((Fn), ##__VA_ARGS__))
