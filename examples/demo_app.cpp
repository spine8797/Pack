#include "vpack/vpack.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <cstdlib>

// Placed in the dedicated ".vcode" section (encrypted on disk when packed).
VPACK_CODE uint64_t compute_protected_signature(uint64_t user_id, uint64_t salt) {
    uint64_t state = user_id ^ 0x5341424C455F434FULL;
    for (int round = 0; round < 16; ++round) {
        state = ((state << 11) | (state >> 53)) + (salt ^ static_cast<uint64_t>(round * 0x9E3779B9u));
        state ^= 0xBF58476D1CE4E5B9ULL;
    }
    return state;
}

namespace {

uint64_t native_mix_helper(uint64_t a, uint64_t b, uint64_t, uint64_t) {
    return (a ^ (b * 0x9E3779B97F4A7C15ULL)) + 0x1337C0DEULL;
}

vpack::vm::VmProgram build_virtualized_verifier(uint64_t dynamic_seed) {
    using namespace vpack::vm;
    BytecodeBuilder b(dynamic_seed);

    b.anti_debug_check()
     .mov_reg(R2, R0)
     .mov_imm(R3, 1)
     .mov_imm(R4, 5)
     .label("loop_start")
     .xor_reg(R2, R3)
     .rol_imm(R2, 7)
     .add_imm(R2, 0x5A5A)
     .add_imm(R3, 1)
     .cmp_reg(R3, R4)
     .jl("loop_start")
     .jz("loop_start")
     .mov_reg(R0, R2)
     .call_native(1, R0)
     .anti_debug_check()
     .ret();

    return b.finalize();
}

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
    std::cout << VPACK_STR("  VPack Protected Process (Live Memory Guard & VM)\n");
    std::cout << VPACK_STR("============================================================\n");

    // 1. Initialize Runtime Protection (Anti-Debug + Anti-Dump + PE Header Erase + PEB Size Tamper + Module Snapshot)
    const auto status = vpack::Protector::initialize(vpack::PROT_DEFAULT);

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
              << VPACK_STR("    - .text Baseline Hash    : 0x") << std::hex << status.text_baseline_hash << "\n"
              << VPACK_STR("    - In-Memory MZ Signature : 0x") << std::hex << mem_mz
              << (mem_mz == 0 ? VPACK_STR(" (WIPED - Anti-Dump Active)\n") : VPACK_STR(" (Present)\n"))
              << VPACK_STR("    - Debugger Threat Flags  : 0x") << std::hex << status.initial_debug_report.flags
              << (status.initial_debug_report.detected() ? VPACK_STR(" [DETECTED]\n") : VPACK_STR(" [CLEAN]\n"))
              << VPACK_STR("    - RDTSC Timing Delta     : ") << std::dec << status.initial_debug_report.rdtsc_delta << VPACK_STR(" cycles\n\n");

    // 3. Execute function inside ".vcode" section
    const uint64_t user_id = 0x1001A5A5ULL;
    const uint64_t salt    = 0x9988776655443322ULL;
    const uint64_t expected_sig = compute_protected_signature(user_id, salt);
    std::cout << VPACK_STR("[2] Protected .vcode Section Execution:\n")
              << VPACK_STR("    - compute_protected_signature() = 0x") << std::hex << expected_sig << std::dec << "\n\n";

    // 4. Execute virtualized function inside the Polymorphic VM Engine
    vpack::vm::VmEngine vm;
    vm.register_native(1, &native_mix_helper);

    vpack::vm::VmProgram prog = build_virtualized_verifier(0xC0FFEE123456789ULL);
    bool vm_ok = false;
    uint64_t expected_vm = vm.run_WithArgs(prog, 0xABCDEF0123456789ULL, user_id, 0, 0, &vm_ok);

    std::cout << VPACK_STR("[3] Polymorphic Virtual Machine Execution:\n")
              << VPACK_STR("    - Encrypted Bytecode Size : ") << prog.bytecode.size() << VPACK_STR(" bytes\n")
              << VPACK_STR("    - VM Execution Status     : ") << (vm_ok ? VPACK_STR("SUCCESS") : VPACK_STR("FAILED")) << "\n"
              << VPACK_STR("    - VM Computed Digest      : 0x") << std::hex << expected_vm << std::dec << "\n";

    vpack::vm::VmProgram tampered_prog = prog;
    tampered_prog.bytecode[tampered_prog.bytecode.size() / 2] ^= 0x01;
    bool tampered_ok = true;
    vm.run_WithArgs(tampered_prog, 0xABCDEF0123456789ULL, user_id, 0, 0, &tampered_ok);
    std::cout << VPACK_STR("    - Bytecode Tamper Test    : ")
              << (!tampered_ok ? VPACK_STR("BLOCKED (Integrity Tag Mismatch)") : VPACK_STR("UNEXPECTED")) << "\n\n";

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
        bool fn_bp = vpack::antidebug::scan_software_breakpoints(
            reinterpret_cast<const void*>(&compute_protected_signature), 16
        );

        uint64_t cur_sig = compute_protected_signature(user_id, salt);
        bool cur_vm_ok = false;
        uint64_t cur_vm = vm.run_WithArgs(prog, 0xABCDEF0123456789ULL, user_id, 0, 0, &cur_vm_ok);
        uint16_t cur_mz = *reinterpret_cast<const uint16_t*>(module_base);

        std::cout << VPACK_STR("  [Tick #") << std::dec << std::setw(2) << tick << VPACK_STR("] ")
                  << VPACK_STR("MZ:0x") << std::hex << cur_mz << " | "
                  << VPACK_STR(".text:") << (env_clean ? VPACK_STR("OK") : VPACK_STR("ALERT")) << " | "
                  << VPACK_STR(".vcode:") << ((!fn_bp && cur_sig == expected_sig) ? VPACK_STR("OK") : VPACK_STR("TAMPERED")) << " | "
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
