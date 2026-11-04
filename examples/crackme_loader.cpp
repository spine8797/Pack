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
// COMPILE-TIME ONLY: Pre-encrypts the secret payload using the exact 8-round
// VM Feistel key schedule so NEITHER the master key NOR the plaintext payload
// ever exists in the compiled binary!
// ============================================================================
constexpr uint64_t compile_time_k1(const char* str, size_t len) noexcept {
    uint64_t k1 = 0x5341424C455F3236ULL;
    for (size_t i = 0; i < len; ++i) {
        k1 = ((k1 << 7) | (k1 >> 57)) ^
             (static_cast<uint64_t>(static_cast<uint8_t>(str[i])) * 0x9E3779B97F4A7C15ULL);
    }
    return k1;
}

constexpr uint64_t compile_time_vm_schedule(uint64_t r0, uint64_t r1) noexcept {
    for (uint64_t r4 = 1; r4 <= 8; ++r4) {
        r0 ^= r1;
        r0 = (r0 << 13) | (r0 >> 51);
        r0 += 0x9E3779B97F4A7C15ULL;
        r1 ^= r0;
        r1 = (r1 >> 17) | (r1 << 47);
        r0 *= r4;
    }
    r0 ^= r1;
    return r0;
}

constexpr uint8_t payload_stream_byte(uint64_t derived_key, size_t i) noexcept {
    uint64_t z = derived_key + static_cast<uint64_t>(i) * 0x9E3779B97F4A7C15ULL;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return static_cast<uint8_t>((z ^ (z >> 31)) & 0xFFu);
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

// Builds the 8-round Polymorphic VM Key-Derivation Program at runtime.
// Inputs:
//   R0 = k0 (FNV-1a 64-bit of user input)
//   R1 = k1 (Rolling mix of user input)
//   R2 = integrity_delta (.text live hash ^ baseline hash -> 0 if unpatched/no INT3)
//   R3 = threat_flags (anti-debug & anti-injection report flags -> 0 if clean)
VPACK_CODE vpack::vm::VmProgram build_key_schedule_vm(uint64_t vm_seed) {
    using namespace vpack::vm;
    BytecodeBuilder b(vm_seed);

    b.anti_debug_check()
     .xor_reg(R0, R2)                        // Poison R0 if .text was patched or breakpointed
     .sub_reg(R1, R3)                        // Poison R1 if debugger/injected DLL detected
     .mov_imm(R4, 1)                         // R4 = round = 1
     .mov_imm(R5, 8)                         // R5 = max_rounds = 8

     .label("feistel_loop")
     .xor_reg(R0, R1)
     .rol_imm(R0, 13)
     .add_imm(R0, 0x9E3779B97F4A7C15ULL)
     .xor_reg(R1, R0)
     .ror_imm(R1, 17)
     .imul_reg(R0, R4)
     .add_imm(R4, 1)
     .cmp_reg(R4, R5)
     .jl("feistel_loop")
     .jz("feistel_loop")

     .xor_reg(R0, R1)
     .xor_reg(R0, R2)
     .xor_reg(R0, R3)
     .anti_debug_check()
     .ret();

    return b.finalize();
}

} // namespace

// Placed in encrypted .vcode (.sbl1) section: derives the 64-bit decryption key via Polymorphic VM
// and attempts to decrypt & verify the secret Loader Vault.
VPACK_CODE bool try_unlock_loader_vault(
    const std::string& user_key,
    uint64_t baseline_text_hash,
    std::string& out_decrypted_payload,
    uint64_t& out_derived_key
) {
    // 1. Live environment, anti-debug, anti-injection & code integrity verification
    vpack::antidebug::DebugReport rep{};
    vpack::Protector::verify_environment(&rep);

    const uint64_t live_text_hash  = vpack::antidump::compute_text_integrity(nullptr);
    const uint64_t integrity_delta = live_text_hash ^ baseline_text_hash;
    const uint64_t threat_flags    = static_cast<uint64_t>(rep.flags);

    // 2. Compute input key material (k0, k1)
    const uint64_t k0 = vpack::crypto::fnv1a_64(user_key.data(), user_key.size());
    uint64_t k1 = 0x5341424C455F3236ULL;
    for (size_t i = 0; i < user_key.size(); ++i) {
        k1 = ((k1 << 7) | (k1 >> 57)) ^
             (static_cast<uint64_t>(static_cast<uint8_t>(user_key[i])) * 0x9E3779B97F4A7C15ULL);
    }

    // 3. Execute 8-round Feistel key derivation inside the Direct-Threaded Polymorphic VM
    const uint64_t dynamic_vm_seed = (__rdtsc() ^ 0x5341424C455F4B59ULL) | 1ULL;
    vpack::vm::VmProgram vm_prog = build_key_schedule_vm(dynamic_vm_seed);
    vpack::vm::VmEngine  vm_engine;

    bool vm_ok = false;
    const uint64_t derived_key = vm_engine.run_WithArgs(
        vm_prog, k0, k1, integrity_delta, threat_flags, &vm_ok
    );
    out_derived_key = derived_key;
    if (!vm_ok) {
        return false;
    }

    // 4. Decrypt the vault payload using the VM-derived 64-bit key
    constexpr size_t kLen = kVault.ciphertext.size();
    out_decrypted_payload.resize(kLen);
    for (size_t i = 0; i < kLen; ++i) {
        out_decrypted_payload[i] = static_cast<char>(
            kVault.ciphertext[i] ^ payload_stream_byte(derived_key, i)
        );
    }

    // 5. Verify decrypted payload integrity hash
    // Note: Patching this check in a debugger only prints garbage ciphertext because
    // the payload bytes themselves are encrypted with `derived_key`!
    const uint64_t dec_hash = vpack::crypto::fnv1a_64(
        out_decrypted_payload.data(), out_decrypted_payload.size()
    );
    return dec_hash == kVault.plain_hash;
}

int main() {
    // 1. Initialize full VPack protection (wipes MZ/PE headers, wipes .vpack, enforces RX/R, hides thread)
    const auto prot = vpack::Protector::initialize(vpack::PROT_DEFAULT);

    // 2. Start background anti-debug & anti-injection watchdog thread (hidden via NtCreateThreadEx)
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
    std::printf("%s", VPACK_STR("  [*] Protection Profile : 2-Stage Packed + Zero-RWX + Threaded VM\n").c_str());
    std::printf("%s", VPACK_STR("  [*] Anti-Dump Status   : PE Headers & .vpack Erased in RAM\n").c_str());
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
        while (!input_key.empty() && (input_key.back() == '\r' || input_key.back() == '\n' || input_key.back() == ' ')) {
            input_key.pop_back();
        }
        if (input_key.empty()) {
            continue;
        }

        uint64_t derived_key = 0;
        if (try_unlock_loader_vault(input_key, prot.text_baseline_hash, unlocked_payload, derived_key)) {
            unlocked     = true;
            unlocked_key = derived_key;
            break;
        } else {
            ++attempts;
            std::printf("%s%d%s0x%016llx)\n",
                        VPACK_STR("  [-] Access Denied! Invalid License Key (Attempt ").c_str(),
                        attempts,
                        VPACK_STR("/5 | VM Digest: ").c_str(),
                        static_cast<unsigned long long>(derived_key));
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
    std::printf("%s", VPACK_STR("============================================================\n").c_str());

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
                        VPACK_STR("      - .text Integrity     : ").c_str(),
                        (clean ? VPACK_STR("VERIFIED CLEAN\n").c_str() : VPACK_STR("TAMPER / ALERT\n").c_str()));
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
