#pragma once

#include "vpack/config.h"
#include "vpack/vm.h"
#include <cstdint>
#include <cstddef>
#include <vector>

namespace vpack::virtualizer {

struct LiftReport {
    bool     success           = false;
    void*    function_address  = nullptr;
    size_t   native_code_size  = 0;
    size_t   decoded_insns     = 0;
    size_t   vm_bytecode_size  = 0;
    uint16_t slot_id           = 0xFFFFu;
    uint64_t vm_seed           = 0;
    bool     native_shredded   = false;
};

// Decodes a compiled x86_64 function starting at `fn_bytes`, fragments its instructions
// into Non-Linear MBA & Hybrid VM micro-operations, and produces a rolling-encrypted VmProgram.
bool lift_x64_function(
    const uint8_t*   fn_bytes,
    size_t           max_scan_bytes,
    uint64_t         vm_seed,
    vm::VmProgram&   out_program,
    size_t*          out_native_size = nullptr,
    size_t*          out_decoded_insns = nullptr
) noexcept;

// Lifts a compiled x86_64 function into the Polymorphic Hybrid VM, verifies mathematical
// equivalence, installs a 12-byte VM entry thunk at `fn_address`, and PERMANENTLY SHREDS
// the remaining native x86_64 machine code in RAM (replacing it with cryptographic noise + UD2)!
LiftReport virtualize_and_shred(
    void*    fn_address,
    size_t   max_scan_bytes = 2048,
    uint64_t custom_seed    = 0
) noexcept;

// Queries whether a function has been lifted into the VM and its native x86_64 code shredded.
bool is_function_virtualized(const void* fn_address, LiftReport* out_report = nullptr) noexcept;

// Executes a registered virtualized function slot using Windows x64 ABI argument mapping.
uint64_t execute_lifted_slot(
    uint16_t slot_id,
    uint64_t rcx_arg,
    uint64_t rdx_arg,
    uint64_t r8_arg,
    uint64_t r9_arg
) noexcept;

} // namespace vpack::virtualizer

#define VPACK_VIRTUALIZE_FN(FnPtr) \
    (::vpack::virtualizer::virtualize_and_shred(reinterpret_cast<void*>(FnPtr)))
