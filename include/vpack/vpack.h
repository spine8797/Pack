#pragma once

#include "vpack/config.h"
#include "vpack/crypto.h"
#include "vpack/anti_debug.h"
#include "vpack/anti_vm.h"
#include "vpack/anti_dump.h"
#include "vpack/page_vault.h"
#include "vpack/vm.h"
#include "vpack/virtualizer.h"
#include "vpack/pe_parser.h"

namespace vpack {

struct RuntimeStatus {
    bool                    initialized = false;
    bool                    packed_binary = false;
    bool                    page_vault_active = false;
    uint32_t                active_flags = PROT_NONE;
    uint64_t                text_baseline_hash = 0;
    antidebug::DebugReport  initial_debug_report{};
    antivm::VmReport        initial_vm_report{};
};

class Protector {
public:
    static RuntimeStatus initialize(uint32_t flags = PROT_DEFAULT) noexcept;

    static bool verify_environment(antidebug::DebugReport* out_report = nullptr) noexcept;

    static uint64_t baseline_text_hash() noexcept { return baseline_hash_; }

private:
    static uint64_t baseline_hash_;
    static bool     headers_erased_;
};

} // namespace vpack
