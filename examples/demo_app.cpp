#include "vpack/vpack.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <cstdlib>

// Placed in the dedicated ".vcode" section: remains encrypted & PAGE_READONLY
// in RAM at rest, decrypted only inside VPACK_JIT_CALL and re-encrypted with a
// mutated rolling key immediately upon return!
VPACK_CODE uint64_t compute_protected_signature(uint64_t user_id, uint64_t salt) {
    uint64_t state = vpack::crypto::mba_xor(user_id, 0xA381E5C9D72B4F19ULL);
    for (int round = 0; round < 16; ++round) {
        uint64_t rot  = (state << 11) | (state >> 53);
        uint64_t term = vpack::crypto::mba_xor(salt, static_cast<uint64_t>(round * 0x9E3779B9u));
        state = vpack::crypto::mba_add(rot, term);
        state = vpack::crypto::mba_xor(state, 0xBF58476D1CE4E5B9ULL);
    }
    return state;
}

namespace {

uint64_t native_mix_helper(uint64_t a, uint64_t b, uint64_t, uint64_t) {
    return vpack::crypto::mba_add(
        vpack::crypto::mba_xor(a, b * 0x9E3779B97F4A7C15ULL),
        0x1337C0DEULL
    );
}

// Compile-Time Assembled & Rolling-Encrypted Hybrid VM Verifier
constexpr auto build_constexpr_verifier() noexcept {
    using namespace vpack::vm;
    ConstexprVmBuilder<256> b(0xC0FFEE123456789ULL);

    b.anti_debug_check()
     .entangle_env(R0)
     .mov_reg(R2, R0)
     .mov_imm(R3, 1)
     .mov_imm(R4, 5)
     .label(0)
     .rotate_regs(3)
     .mba_xor(R2, R3)
     .rol_imm(R2, 7)
     .add_imm(R2, 0x5A5A)
     .add_imm(R3, 1)
     .cmp_reg(R3, R4)
     .jl(0)
     .jz(0)
     .mov_reg(R0, R2)
     .state_matrix(0x3C)
     .call_native(1, R0)
     .anti_debug_check()
     .ret();

    return b.finalize();
}

static constexpr auto kCompiledVerifier = build_constexpr_verifier();

} // namespace

int main(int argc, char** argv) {
    // Parse optional arguments:
    //   --once             : run single check and exit
    //   --keep-alive <sec> : run persistent security monitor for <sec> seconds (0 = infinite)
    bool persistent_mode = true;
    uint32_t max_seconds = 0; // 0 = infinite loop until Ctrl+C

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--once") {
            persistent_mode = false;
        } else if (arg == "--keep-alive" && i + 1 < argc) {
            persistent_mode = true;
            max_seconds = static_cast<uint32_t>(std::strtoul(argv[++i], nullptr, 10));
        }
    }

    std::cout << VPACK_STR("============================================================\n");
    std::cout << VPACK_STR("  VPack Protected Process (JIT Execute&Wipe + Hybrid MBA VM)\n");
    std::cout << VPACK_STR("============================================================\n");

    // 1. Initialize Runtime Protection (Anti-Debug + Anti-Dump + PE Header Erase + JIT .vcode Vault)
    const auto status = vpack::Protector::initialize(vpack::PROT_DEFAULT);

    // 1b. Lift native x86_64 machine code of compute_protected_signature into the Polymorphic Hybrid VM
    //     and PERMANENTLY SHRED its native x86_64 instructions in RAM!
    const auto lift_rep = VPACK_VIRTUALIZE_FN(&compute_protected_signature);

    const auto* module_base = reinterpret_cast<const uint8_t*>(GetModuleHandleW(nullptr));
    const uint16_t mem_mz = *reinterpret_cast<const uint16_t*>(module_base);

    // 2. Hidden Import Resolution
    using FnGetCurrentProcessId = DWORD(WINAPI*)();
    using FnSleep               = VOID(WINAPI*)(DWORD);
    auto hidden_get_pid = VPACK_IMPORT(FnGetCurrentProcessId, "kernel32.dll", "GetCurrentProcessId");
    auto hidden_sleep   = VPACK_IMPORT(FnSleep, "kernel32.dll", "Sleep");
    DWORD pid = hidden_get_pid();

    std::cout << VPACK_STR("[1] Runtime Protection Status:\n")
              << VPACK_STR("    - Process ID (PID)       : ") << std::dec << pid << "\n"
              << VPACK_STR("    - Base Address           : 0x") << std::hex << reinterpret_cast<uintptr_t>(module_base) << "\n"
              << VPACK_STR("    - Packed Binary (.vpack) : ") << (status.packed_binary ? VPACK_STR("YES") : VPACK_STR("NO (Unpacked Dev Build)")) << "\n"
              << VPACK_STR("    - .vcode JIT Vault       : ") << (vpack::antidump::is_vcode_jit_active() ? VPACK_STR("ACTIVE (Encrypted & PAGE_READONLY at Rest)") : VPACK_STR("INACTIVE")) << "\n"
              << VPACK_STR("    - x64->VM Lifter & Shred : ") << (lift_rep.native_shredded ? VPACK_STR("SHREDDED (") : VPACK_STR("INACTIVE ("))
              << std::dec << lift_rep.decoded_insns << VPACK_STR(" x64 insns -> ")
              << lift_rep.vm_bytecode_size << VPACK_STR(" VM bytes, native x64 wiped!)\n")
              << VPACK_STR("    - .text Baseline Hash    : 0x") << std::hex << status.text_baseline_hash << "\n"
              << VPACK_STR("    - In-Memory MZ Signature : 0x") << std::hex << mem_mz
              << (mem_mz == 0 ? VPACK_STR(" (WIPED - Anti-Dump Active)\n") : VPACK_STR(" (Present)\n"))
              << VPACK_STR("    - Debugger Threat Flags  : 0x") << std::hex << status.initial_debug_report.flags
              << (status.initial_debug_report.detected() ? VPACK_STR(" [DETECTED]\n") : VPACK_STR(" [CLEAN]\n"))
              << VPACK_STR("    - RDTSC Timing Delta     : ") << std::dec << status.initial_debug_report.rdtsc_delta << VPACK_STR(" cycles\n\n");

    // 3. Execute function inside ".vcode" section via JIT Execute & Wipe Guard
    const uint64_t user_id = 0x1001A5A5ULL;
    const uint64_t salt    = 0x9988776655443322ULL;
    const uint64_t expected_sig = VPACK_JIT_CALL(compute_protected_signature, user_id, salt);
    std::cout << VPACK_STR("[2] Protected .vcode Section Execution (JIT Execute & Re-Encrypt):\n")
              << VPACK_STR("    - compute_protected_signature() = 0x") << std::hex << expected_sig
              << VPACK_STR(" (JIT Gen #") << std::dec << vpack::antidump::vcode_jit_generation() << VPACK_STR(")\n\n");

    // 4. Execute compile-time assembled function inside the Hybrid Polymorphic VM Engine
    vpack::vm::VmEngine vm;
    vm.register_native(1, &native_mix_helper);

    vpack::vm::VmProgram prog = kCompiledVerifier.to_program();
    bool vm_ok = false;
    uint64_t expected_vm = vm.run_WithArgs(prog, 0xABCDEF0123456789ULL, user_id, 0, 0, &vm_ok);

    std::cout << VPACK_STR("[3] Hybrid Polymorphic Virtual Machine Execution:\n")
              << VPACK_STR("    - Encrypted Bytecode Size : ") << prog.bytecode.size() << VPACK_STR(" bytes\n")
              << VPACK_STR("    - VM Execution Status     : ") << (vm_ok ? VPACK_STR("SUCCESS") : VPACK_STR("FAILED")) << "\n"
              << VPACK_STR("    - VM Computed Digest      : 0x") << std::hex << expected_vm << std::dec << "\n";

    vpack::vm::VmProgram tampered_prog = prog;
    tampered_prog.bytecode[tampered_prog.bytecode.size() / 2] ^= 0x01;
    bool tampered_ok = true;
    vm.run_WithArgs(tampered_prog, 0xABCDEF0123456789ULL, user_id, 0, 0, &tampered_ok);
    std::cout << VPACK_STR("    - Bytecode Tamper Test    : ")
              << (!tampered_ok ? VPACK_STR("BLOCKED (Ciphertext MAC Mismatch)") : VPACK_STR("UNEXPECTED")) << "\n\n";

    if (!persistent_mode) {
        vpack::antidebug::DebugReport live_report{};
        bool env_clean = vpack::Protector::verify_environment(&live_report);
        std::cout << VPACK_STR("[4] Final Integrity Check: ")
                  << (env_clean ? VPACK_STR("VERIFIED CLEAN") : VPACK_STR("TAMPER DETECTED")) << "\n";
        return 0;
    }

    std::cout << VPACK_STR("[4] Entering Persistent Memory Security Guard Loop (PID: ") << pid << VPACK_STR(")...\n");
    std::cout.flush();

    uint32_t tick = 0;
    while (max_seconds == 0 || tick < max_seconds) {
        hidden_sleep(1000);
        ++tick;

        vpack::antidebug::DebugReport rep{};
        bool env_clean = vpack::Protector::verify_environment(&rep);
        bool vcode_intact = vpack::antidump::verify_vcode_integrity();

        uint64_t cur_sig = VPACK_JIT_CALL(compute_protected_signature, user_id, salt);
        bool cur_vm_ok = false;
        uint64_t cur_vm = vm.run_WithArgs(prog, 0xABCDEF0123456789ULL, user_id, 0, 0, &cur_vm_ok);
        uint16_t cur_mz = *reinterpret_cast<const uint16_t*>(module_base);

        std::cout << VPACK_STR("  [Tick #") << std::dec << std::setw(2) << tick << VPACK_STR("] ")
                  << VPACK_STR("MZ:0x") << std::hex << cur_mz << " | "
                  << VPACK_STR(".text:") << (env_clean ? VPACK_STR("OK") : VPACK_STR("ALERT")) << " | "
                  << VPACK_STR(".vcode:") << ((vcode_intact && cur_sig == expected_sig) ? VPACK_STR("JIT_OK") : VPACK_STR("TAMPERED"))
                  << VPACK_STR("(G#") << std::dec << vpack::antidump::vcode_jit_generation() << ") | "
                  << VPACK_STR("VM:") << ((cur_vm_ok && cur_vm == expected_vm) ? VPACK_STR("OK") : VPACK_STR("TAMPERED"));

        if (rep.flags & vpack::antidebug::THREAT_DLL_INJECTED) {
            std::cout << VPACK_STR(" | [!] INJECTED DLL DETECTED: ")
                      << rep.injected_module_name
                      << VPACK_STR(" @ 0x") << std::hex << reinterpret_cast<uintptr_t>(rep.injected_module_base);
        } else if (rep.detected()) {
            std::cout << VPACK_STR(" | [!] THREAT FLAGS: 0x") << std::hex << rep.flags;
        } else {
            std::cout << VPACK_STR(" | Status: SECURE");
        }
        std::cout << std::dec << "\n";
        std::cout.flush();
    }

    std::cout << VPACK_STR("[+] Persistent Security Guard Loop finished cleanly.\n");
    return 0;
}
