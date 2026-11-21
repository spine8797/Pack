#pragma once

#include "vpack/config.h"
#include "vpack/vm.h"
#include <cstdint>
#include <cstddef>
#include <vector>

namespace vpack::virtualizer {

using ThunkFnPtr = uint64_t(*)(uint64_t, uint64_t, uint64_t, uint64_t) noexcept;

constexpr size_t   kMaxVirtualizedSlots = 16;
constexpr uint64_t kAotSlotMagic        = 0x9F81E3A5C72B4D19ULL;

struct LiftReport {
    bool     success           = false;
    void*    function_address  = nullptr;
    size_t   native_code_size  = 0;
    size_t   decoded_insns     = 0;
    size_t   vm_bytecode_size  = 0;
    uint16_t slot_id           = 0xFFFFu;
    uint64_t vm_seed           = 0;
    bool     native_shredded   = false;
    bool     aot_pre_lifted    = false;
};

#pragma pack(push, 1)
struct AotVirtualSlotRaw {
    uint64_t magic;
    uint16_t slot_id;
    uint16_t pre_lifted;
    uint32_t bytecode_size;
    uint64_t target_fn_va;
    uint64_t thunk_fn_va;
    uint64_t vm_seed;
    uint64_t integrity_tag;
    uint32_t native_code_size;
    uint32_t decoded_insns;
    uint8_t  bytecode[2048];
};

template <typename TargetFnT>
struct AotVirtualSlotT {
    uint64_t   magic;
    uint16_t   slot_id;
    uint16_t   pre_lifted;
    uint32_t   bytecode_size;
    TargetFnT  target_fn;
    ThunkFnPtr thunk_fn;
    uint64_t   vm_seed;
    uint64_t   integrity_tag;
    uint32_t   native_code_size;
    uint32_t   decoded_insns;
    uint8_t    bytecode[2048];
};
#pragma pack(pop)

static_assert(sizeof(AotVirtualSlotRaw) == 2104, "AotVirtualSlotRaw size mismatch");

// Decodes a compiled x86_64 function starting at `fn_bytes`, fragments its instructions
// into Non-Linear MBA & Hybrid VM micro-operations, and produces a rolling-encrypted VmProgram.
bool lift_x64_function(
    const uint8_t*   fn_bytes,
    size_t           max_scan_bytes,
    uint64_t         vm_seed,
    vm::VmProgram&   out_program,
    size_t*          out_native_size = nullptr,
    size_t*          out_decoded_insns = nullptr,
    uint32_t         fn_rva = 0
) noexcept;

// Lifts a compiled x86_64 function into the Polymorphic Hybrid VM, verifies mathematical
// equivalence, installs a VM entry thunk at `fn_address`, and PERMANENTLY SHREDS
// the remaining native x86_64 machine code in RAM!
LiftReport virtualize_and_shred(
    void*    fn_address,
    size_t   max_scan_bytes = 2048,
    uint64_t custom_seed    = 0
) noexcept;

// Activates a compile-time registered AOT slot (already lifted & shredded on disk by vpack_cli pack)
// or falls back to runtime virtualize_and_shred in unpacked dev builds.
LiftReport activate_aot_or_runtime_slot(AotVirtualSlotRaw* raw_slot) noexcept;

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

template <uint16_t Slot>
uint64_t vm_slot_thunk(uint64_t rcx_arg, uint64_t rdx_arg, uint64_t r8_arg, uint64_t r9_arg) noexcept {
    return execute_lifted_slot(Slot, rcx_arg, rdx_arg, r8_arg, r9_arg);
}

} // namespace vpack::virtualizer

#define VPACK_VIRTUALIZE_FN_SLOT(FnPtr, CounterVal) \
    ([]() noexcept -> ::vpack::virtualizer::LiftReport { \
        using FnT = decltype(FnPtr); \
        constexpr uint16_t kSlotId = static_cast<uint16_t>((CounterVal) % ::vpack::virtualizer::kMaxVirtualizedSlots); \
        alignas(8) static ::vpack::virtualizer::AotVirtualSlotT<FnT> s_aot_slot = { \
            ::vpack::virtualizer::kAotSlotMagic, \
            kSlotId, 0, 0, \
            (FnPtr), \
            &::vpack::virtualizer::vm_slot_thunk<kSlotId>, \
            0, 0, 0, 0, {} \
        }; \
        return ::vpack::virtualizer::activate_aot_or_runtime_slot( \
            reinterpret_cast<::vpack::virtualizer::AotVirtualSlotRaw*>(&s_aot_slot) \
        ); \
    }())

#define VPACK_VIRTUALIZE_FN(FnPtr) VPACK_VIRTUALIZE_FN_SLOT(FnPtr, __COUNTER__)
