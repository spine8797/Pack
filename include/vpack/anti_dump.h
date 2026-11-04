#pragma once

#include "vpack/config.h"
#include "vpack/crypto.h"
#include <cstdint>
#include <cstddef>

namespace vpack::antidump {

struct ModuleLayoutInfo {
    void*       base_address = nullptr;
    uint32_t    original_size_of_image = 0;
    const void* text_section_base = nullptr;
    size_t      text_section_size = 0;
    uint64_t    text_section_hash = 0;
};

bool query_module_layout(void* module_base, ModuleLayoutInfo& out_info) noexcept;

bool erase_pe_headers(void* module_base = nullptr) noexcept;

bool tamper_peb_image_size(uint32_t fake_size_delta = 0x01000000u) noexcept;

uint64_t compute_text_integrity(void* module_base = nullptr) noexcept;
bool verify_text_integrity(uint64_t expected_hash, void* module_base = nullptr) noexcept;

uint32_t capture_module_baseline() noexcept;
bool detect_injected_module(void** out_base = nullptr, char* out_name = nullptr, size_t max_len = 0) noexcept;

void* resolve_export_by_hash(uint64_t module_hash_ci, uint64_t proc_hash_ci) noexcept;

template <typename FnPtr>
class HiddenImport {
public:
    constexpr HiddenImport(uint64_t mod_hash, uint64_t fn_hash) noexcept
        : mod_hash_(mod_hash), fn_hash_(fn_hash), encoded_ptr_(0) {}

    FnPtr get() noexcept {
        constexpr uint64_t kMask = 0xD6E8FEB86659FD93ULL;
        if (encoded_ptr_ == 0) {
            void* raw = resolve_export_by_hash(mod_hash_, fn_hash_);
            encoded_ptr_ = reinterpret_cast< uintptr_t >(raw) ^ static_cast<uintptr_t>(mod_hash_ ^ fn_hash_ ^ kMask);
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
