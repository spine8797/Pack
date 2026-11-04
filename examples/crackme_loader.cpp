#include "vpack/vpack.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdio>
#include <cinttypes>
#include <string>
#include <array>
#include <cstring>

namespace {

// ============================================================================
// COMPILE-TIME ONLY: Pre-encrypts the secret payload AND compiles the Hybrid
// VM Bytecode at C++ compile-time so NEITHER the master key, NOR the plaintext
// payload, NOR any BytecodeBuilder function calls ever exist in the binary!
// ============================================================================
constexpr uint64_t compile_time_k1(const char* str, size_t len) noexcept {
    uint64_t k1 = 0x8F91D3A5C7E24B19ULL;
    for (size_t i = 0; i < len; ++i) {
        k1 = ((k1 << 7) | (k1 >> 57)) ^
             (static_cast<uint64_t>(static_cast<uint8_t>(str[i])) * 0x9E3779B97F4A7C15ULL);
    }
    return k1;
}

// Exact mathematical mirror of the Hybrid VM (Non-Linear MBA + GF(2^64) +
// State-Matrix Automaton + Dynamic Register Rotation + Encrypted Stack)
constexpr uint64_t compile_time_vm_schedule(uint64_t r0, uint64_t r1) noexcept {
    for (uint64_t r4 = 1; r4 <= 8; ++r4) {
        r0 = vpack::crypto::mba_xor(r0, r1);
        r0 = (r0 << 13) | (r0 >> 51);
        r0 = vpack::crypto::mba_add(r0, 0x9E3779B97F4A7C15ULL);
        r1 = vpack::crypto::mba_xor(r1, r0);
        r1 = (r1 >> 17) | (r1 << 47);
        r0 *= r4;

        // Hybrid State-Matrix transformation (mkey = 0x5A)
        const uint64_t k  = static_cast<uint64_t>(0x5Au) * 0x9E3779B97F4A7C15ULL;
        const uint64_t f0 = vpack::crypto::gf2_64_mul(r1 ^ k, 0xBF58476D1CE4E5B9ULL | 1ULL);
        const uint64_t n0 = vpack::crypto::mba_xor(r0, vpack::crypto::mba_add(f0, r1 * 0x94D049BB133111EBULL));
        const uint64_t f1 = vpack::crypto::poly_permute_64(n0, k ^ 0xE791C3A58B2D4F19ULL);
        const uint64_t n1 = vpack::crypto::mba_xor(r1, f1);
        r0 = n0;
        r1 = n1;
    }
    r0 = vpack::crypto::mba_xor(r0, r1);
    return r0;
}

constexpr uint8_t payload_stream_byte(uint64_t derived_key, size_t i) noexcept {
    return vpack::crypto::poly_stream_byte(derived_key, i);
}

template <size_t N>
struct CompileTimeVault {
    std::array<uint8_t, N - 1> ciphertext{};
    uint64_t                   plain_hash = 0;

    constexpr CompileTimeVault(const char (&master_key)[26], const char (&secret_payload)[N]) noexcept {
        const uint64_t k0 = vpack::crypto::fnv1a_64_constexpr(master_key, 25);
        const uint64_t k1 = compile_time_k1(master_key, 25);
        const uint64_t dk = compile_time_vm_schedule(k0, k1);

        plain_hash = vpack::crypto::fnv1a_64_constexpr(secret_payload, N - 1);
        for (size_t i = 0; i < N - 1; ++i) {
            ciphertext[i] = static_cast<uint8_t>(secret_payload[i]) ^ payload_stream_byte(dk, i);
        }
    }
};

// Master Key (compile-time only, never stored in binary): "SABLE-7F4A-9E37-C0DE-2026"
// Secret Payload (compile-time only, never stored in binary):
static constexpr CompileTimeVault kVault(
    "SABLE-7F4A-9E37-C0DE-2026",
    "FLAG{SABLE_VM_UNPATCHABLE_2026} :: VIP Loader Stage Unlocked & Active!"
);

// ============================================================================
// COMPILE-TIME ASSEMBLED & ROLLING-ENCRYPTED HYBRID VM PROGRAM
// No runtime BytecodeBuilder calls exist anywhere in the binary!
// ============================================================================
constexpr auto build_constexpr_key_vm() noexcept {
    using namespace vpack::vm;
    ConstexprVmBuilder<256> b(0x9C81E5A3D72B4F19ULL);

    b.anti_debug_check()
     .entangle_env(R0)                       // Silent environmental key poison (PEB + KUSER + Syscall DebugPort)
     .mba_xor(R0, R2)                        // Poison R0 if .text or .vcode was patched/breakpointed
     .mba_sub(R1, R3)                        // Poison R1 if debugger/injected DLL/hook detected
     .mov_imm(R4, 1)                         // R4 = round = 1
     .mov_imm(R5, 8)                         // R5 = max_rounds = 8

     .label(0)                               // OP_SYNC_STATE + feistel_loop target
     .rotate_regs(3)                         // Rotate physical-virtual register mapping dynamically
     .mba_xor(R0, R1)
     .rol_imm(R0, 13)
     .add_imm(R0, 0x9E3779B97F4A7C15ULL)
     .mba_xor(R1, R0)
     .ror_imm(R1, 17)
     .imul_reg(R0, R4)
     .push(R0)                               // Bipartite encrypted stack round-trip
     .pop(R0)
     .state_matrix(0x5A)                     // GF(2^64) x Z_{2^64} 2x2 State-Matrix Automaton
     .add_imm(R4, 1)
     .cmp_reg(R4, R5)
     .jl(0)
     .jz(0)

     .mba_xor(R0, R1)
     .mba_xor(R0, R2)
     .mba_xor(R0, R3)
     .entangle_env(R0)
     .anti_debug_check()
     .ret();

    return b.finalize();
}

static constexpr auto kCompiledKeyVm = build_constexpr_key_vm();

} // namespace

// Placed in JIT-encrypted .vcode (.sbl1) section: remains encrypted & PAGE_READONLY
// in RAM at rest, decrypted only inside VPACK_JIT_CALL and re-encrypted with a new
// rolling key immediately on return!
VPACK_CODE bool try_unlock_loader_vault(
    const std::string& user_key,
    uint64_t baseline_text_hash,
    std::string& out_decrypted_payload,
    uint64_t& out_derived_key
) {
    // 1. Live environment, anti-debug (Indirect Syscall), anti-injection & code integrity verification
    vpack::antidebug::DebugReport rep{};
    vpack::Protector::verify_environment(&rep);

    const uint64_t live_text_hash  = vpack::antidump::compute_text_integrity(nullptr);
    const uint64_t integrity_delta = vpack::crypto::mba_xor(live_text_hash, baseline_text_hash);
    const uint64_t threat_flags    = static_cast<uint64_t>(rep.flags) ^
                                     vpack::antidebug::compute_environmental_key_poison();

    // 2. Compute input key material (k0, k1) with Non-Linear MBA
    const uint64_t k0 = vpack::crypto::fnv1a_64(user_key.data(), user_key.size());
    uint64_t k1 = 0x8F91D3A5C7E24B19ULL;
    for (size_t i = 0; i < user_key.size(); ++i) {
        uint64_t rot = (k1 << 7) | (k1 >> 57);
        uint64_t term = static_cast<uint64_t>(static_cast<uint8_t>(user_key[i])) * 0x9E3779B97F4A7C15ULL;
        k1 = vpack::crypto::mba_xor(rot, term);
    }

    // 3. Execute pre-compiled Hybrid VM program (Instruction-Chained Rolling Key + State Matrix)
    vpack::vm::VmProgram vm_prog = kCompiledKeyVm.to_program();
    vpack::vm::VmEngine  vm_engine;

    bool vm_ok = false;
    const uint64_t derived_key = vm_engine.run_WithArgs(
        vm_prog, k0, k1, integrity_delta, threat_flags, &vm_ok
    );
    out_derived_key = derived_key;
    if (!vm_ok || vpack::crypto::opaque_false(derived_key)) {
        return false;
    }

    // 4. Decrypt the vault payload using the VM-derived 64-bit GF(2^64)/MBA polynomial stream
    constexpr size_t kLen = kVault.ciphertext.size();
    out_decrypted_payload.resize(kLen);
    for (size_t i = 0; i < kLen; ++i) {
        out_decrypted_payload[i] = static_cast<char>(
            kVault.ciphertext[i] ^ payload_stream_byte(derived_key, i)
        );
    }

    // 5. Verify decrypted payload integrity hash
    const uint64_t dec_hash = vpack::crypto::fnv1a_64(
        out_decrypted_payload.data(), out_decrypted_payload.size()
    );
    return dec_hash == kVault.plain_hash;
}

int main() {
    // 1. Initialize full VPack protection (wipes MZ/PE headers, wipes .vpack, locks .vcode in JIT vault)
    const auto prot = vpack::Protector::initialize(vpack::PROT_DEFAULT);

    // 2. Start background anti-debug & anti-injection watchdog thread (hidden via Indirect Syscall)
    vpack::antidebug::Watchdog watchdog;
    watchdog.start(150, [](const vpack::antidebug::DebugReport&) {});

    using FnGetCurrentProcessId = DWORD(WINAPI*)();
    using FnSleep               = VOID(WINAPI*)(DWORD);
    auto hidden_get_pid = VPACK_IMPORT(FnGetCurrentProcessId, "kernel32.dll", "GetCurrentProcessId");
    auto hidden_sleep   = VPACK_IMPORT(FnSleep, "kernel32.dll", "Sleep");

    const auto* module_base = reinterpret_cast<const uint8_t*>(GetModuleHandleW(nullptr));

    std::printf("%s", VPACK_STR("============================================================\n").c_str());
    std::printf("%s", VPACK_STR("  SABLE VPack Protected Loader & CrackMe Challenge\n").c_str());
    std::printf("%s", VPACK_STR("============================================================\n").c_str());
    std::printf("%s%lu\n", VPACK_STR("  [*] Process ID         : ").c_str(), static_cast<unsigned long>(hidden_get_pid()));
    std::printf("%s0x%llx\n", VPACK_STR("  [*] Base Address       : ").c_str(),
                static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(module_base)));
    std::printf("%s", VPACK_STR("  [*] Protection Profile : JIT Execute&Wipe + Hybrid MBA VM + Indirect Syscall\n").c_str());
    std::printf("%s", VPACK_STR("  [*] Anti-Dump Status   : PE Headers Wiped & .vcode Encrypted at Rest in RAM\n").c_str());
    std::printf("%s", VPACK_STR("------------------------------------------------------------\n").c_str());

    int attempts = 0;
    bool unlocked = false;
    std::string unlocked_payload;
    uint64_t unlocked_key = 0;

    while (attempts < 5) {
        std::printf("%s", VPACK_STR("\n  [?] Enter License Key: ").c_str());
        std::fflush(stdout);

        char line_buf[256]{};
        if (!std::fgets(line_buf, sizeof(line_buf), stdin)) {
            break;
        }
        std::string input_key(line_buf);
        vpack::crypto::secure_wipe(line_buf, sizeof(line_buf), attempts);

        while (!input_key.empty() && (input_key.back() == '\r' || input_key.back() == '\n' || input_key.back() == ' ')) {
            input_key.pop_back();
        }
        if (input_key.empty()) {
            continue;
        }

        uint64_t derived_key = 0;
        // Invoke .vcode function via JIT Execute & Wipe Guard (decrypts -> runs -> re-encrypts with new key)
        bool ok = VPACK_JIT_CALL(
            try_unlock_loader_vault,
            input_key,
            prot.text_baseline_hash,
            unlocked_payload,
            derived_key
        );
        vpack::crypto::secure_wipe(&input_key[0], input_key.size(), derived_key);

        if (ok) {
            unlocked     = true;
            unlocked_key = derived_key;
            break;
        } else {
            vpack::crypto::secure_wipe(&unlocked_payload[0], unlocked_payload.size(), derived_key);
            unlocked_payload.clear();
            ++attempts;
            std::printf("%s%d%s0x%016llx | JIT Gen #%llu)\n",
                        VPACK_STR("  [-] Access Denied! Invalid License Key (Attempt ").c_str(),
                        attempts,
                        VPACK_STR("/5 | VM Digest: ").c_str(),
                        static_cast<unsigned long long>(derived_key),
                        static_cast<unsigned long long>(vpack::antidump::vcode_jit_generation()));
        }
    }

    if (!unlocked) {
        std::printf("%s", VPACK_STR("\n  [!] Authentication Failed. Exiting Loader.\n").c_str());
        watchdog.stop();
        return 1;
    }

    std::printf("%s", VPACK_STR("\n============================================================\n").c_str());
    std::printf("%s", VPACK_STR("  [+] ACCESS GRANTED - LOADER VAULT UNLOCKED!\n").c_str());
    std::printf("%s0x%016llx\n", VPACK_STR("  [+] VM Derived Key    : ").c_str(),
                static_cast<unsigned long long>(unlocked_key));
    std::printf("%s%s\n", VPACK_STR("  [+] Decrypted Payload : ").c_str(), unlocked_payload.c_str());
    std::printf("%s%llu\n", VPACK_STR("  [+] .vcode JIT Re-Key : Generation #").c_str(),
                static_cast<unsigned long long>(vpack::antidump::vcode_jit_generation()));
    std::printf("%s", VPACK_STR("============================================================\n").c_str());

    // Immediately wipe the unlocked plaintext payload from RAM after displaying it!
    vpack::crypto::secure_wipe(&unlocked_payload[0], unlocked_payload.size(), unlocked_key);
    unlocked_payload.clear();

    while (true) {
        std::printf("%s", VPACK_STR("\n  --- [ Protected Loader Menu ] ---\n").c_str());
        std::printf("%s", VPACK_STR("  [1] Verify Memory & Anti-Dump Status\n").c_str());
        std::printf("%s", VPACK_STR("  [2] Run Live Security Guard Loop (10s)\n").c_str());
        std::printf("%s", VPACK_STR("  [3] Exit Loader\n").c_str());
        std::printf("%s", VPACK_STR("  Select option [1-3]: ").c_str());
        std::fflush(stdout);

        char choice_buf[64]{};
        if (!std::fgets(choice_buf, sizeof(choice_buf), stdin)) {
            break;
        }
        std::string choice(choice_buf);
        while (!choice.empty() && (choice.back() == '\r' || choice.back() == '\n' || choice.back() == ' ')) {
            choice.pop_back();
        }

        if (choice == "1") {
            vpack::antidebug::DebugReport rep{};
            bool clean = vpack::Protector::verify_environment(&rep);
            uint16_t mz = *reinterpret_cast<const uint16_t*>(module_base);
            std::printf("%s", VPACK_STR("\n  [+] Memory Security Status:\n").c_str());
            std::printf("%s0x%04x%s",
                        VPACK_STR("      - In-Memory MZ Header : ").c_str(),
                        static_cast<unsigned>(mz),
                        (mz == 0 ? VPACK_STR(" (WIPED)\n").c_str() : VPACK_STR(" (Present)\n").c_str()));
            std::printf("%s%s",
                        VPACK_STR("      - .text & .vcode Hash : ").c_str(),
                        (clean ? VPACK_STR("VERIFIED CLEAN (Encrypted at Rest)\n").c_str() : VPACK_STR("TAMPER / ALERT\n").c_str()));
            std::printf("%s#%llu\n",
                        VPACK_STR("      - .vcode JIT Gen      : ").c_str(),
                        static_cast<unsigned long long>(vpack::antidump::vcode_jit_generation()));
            std::printf("%s0x%x\n", VPACK_STR("      - Threat Flags        : ").c_str(), rep.flags);
            if (rep.flags & vpack::antidebug::THREAT_DLL_INJECTED) {
                std::printf("%s%s @ 0x%llx\n",
                            VPACK_STR("      - [!] Injected DLL    : ").c_str(),
                            rep.injected_module_name,
                            static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(rep.injected_module_base)));
            }
        } else if (choice == "2") {
            std::printf("%s", VPACK_STR("\n  [*] Monitoring Process Memory for 10 seconds...\n").c_str());
            for (int t = 1; t <= 10; ++t) {
                hidden_sleep(1000);
                vpack::antidebug::DebugReport rep{};
                bool clean = vpack::Protector::verify_environment(&rep);
                std::printf("%s%d%s%s",
                            VPACK_STR("      [Tick #").c_str(),
                            t,
                            VPACK_STR("/10] Integrity: ").c_str(),
                            (clean ? VPACK_STR("OK").c_str() : VPACK_STR("ALERT").c_str()));
                if (rep.flags & vpack::antidebug::THREAT_DLL_INJECTED) {
                    std::printf("%s%s", VPACK_STR(" | [!] Injected DLL: ").c_str(), rep.injected_module_name);
                }
                std::printf("\n");
                std::fflush(stdout);
            }
        } else if (choice == "3" || choice == "exit" || choice == "quit") {
            break;
        }
    }

    watchdog.stop();
    return 0;
}
