#include "vpack/vpack.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <intrin.h>
#include <cstring>

namespace vpack {

uint64_t Protector::baseline_hash_ = 0;
bool     Protector::headers_erased_ = false;

namespace {

uint8_t* g_vinit_base          = nullptr;
size_t   g_vinit_size          = 0;
uint64_t g_runtime_master_seed = 0xB7E193C58A2F4D91ULL;

constexpr uint64_t kGold64      = 0x9E3779B97F4A7C15ULL;
constexpr uint64_t kLiveKeySalt = 0x59E3779B7F4A7C15ULL;

// Runtime scratch slot contract with Stage 2 (offsets inside the stub section,
// strictly below 0x8F0 so vcode_rva/vcode_size/vinit_rva/vinit_size are NEVER overwritten):
constexpr uint32_t kScrPubSaltFinal  = 0x8D0;  // runtime-stashed public_salt (8B)
constexpr uint32_t kScrLiveVcodeKey  = 0x8D8;  // masked live .vcode boot key (8B)
constexpr uint32_t kScrTlsCbPair    = 0x8E0;  // cb0_rva | (cb1_rva << 32) for EpStub replay

VPACK_FORCEINLINE uint64_t rotl64_local(uint64_t x, int n) noexcept {
    return (x << n) | (x >> (64 - n));
}

// Reconstructs the exact anti-debug poison that Stage 2 mixed into the handshake
// base and every region/bridge key (BeingDebugged<<13 ^ KdDebuggerEnabled<<17).
// MUST mirror emit_stage2 byte-for-byte or the SDK miscomputes the handshake base.
VPACK_FORCEINLINE uint64_t compute_runtime_poison() noexcept {
#if defined(_M_X64) || defined(__x86_64__)
    const auto* peb = reinterpret_cast<const uint8_t*>(__readgsqword(0x60));
    const uint64_t bd = static_cast<uint64_t>(peb[0x02]);
    const volatile uint8_t* kd = reinterpret_cast<const volatile uint8_t*>(0x7FFE02D4ULL);
    return (bd << 13) ^ ((static_cast<uint64_t>(*kd) & 1ULL) << 17);
#else
    return 0;
#endif
}

// SDK-side mirror of the masked live .vcode boot key stash (Stage 2):
//   [hdr+0x8EC] = K_live ^ rotl64(pub_salt * GOLD64 + kLiveKeySalt, 17)
VPACK_FORCEINLINE uint64_t unmask_live_vcode_key(uint64_t public_salt, uint64_t masked) noexcept {
    uint64_t m = public_salt * kGold64 + kLiveKeySalt;
    m = rotl64_local(m, 17);
    return masked ^ m;
}

// Registers decrypted .pdata unwind table, initializes the JIT Execute & Wipe vault for
// protected code, restores the original TLS callback slot, wipes the entire stub section
// (header, decoys, bridge, EpStub, TlsStub, Stage 1), and restores strict RX / R section
// permissions. All header fields are unmasked with the runtime handshake base
// (pub_salt ^ ImageBase ^ poison) — a rebuild without executing Stage 2 fails this.
VPACK_INIT_CODE bool finalize_vpack_section_in_memory(uint32_t flags) noexcept {
    auto* base = reinterpret_cast<uint8_t*>(GetModuleHandleW(nullptr));
    if (!base) return false;

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return true; // Headers already wiped
    }

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return true;
    }

    using FnVirtualProtect      = BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD);
    using FnRtlAddFunctionTable = BOOLEAN(NTAPI*)(PRUNTIME_FUNCTION, DWORD, DWORD64);
    static auto fn_vprotect = VPACK_IMPORT(FnVirtualProtect, "kernel32.dll", "VirtualProtect");
    static auto fn_add_ft   = VPACK_IMPORT(FnRtlAddFunctionTable, "kernel32.dll", "RtlAddFunctionTable");

    bool     found_vpack = false;
    uint32_t vpack_rva   = 0xFFFFFFFFu;
    uint32_t vcode_rva   = 0;
    uint32_t vcode_size  = 0;
    uint32_t vinit_rva   = 0;
    uint32_t vinit_size  = 0;
    uint64_t live_boot_key = 0;

    const IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    const WORD num_sec = nt->FileHeader.NumberOfSections;

    const uint64_t poison = compute_runtime_poison();
    const uint64_t img_base_u64 = reinterpret_cast<uint64_t>(base);

    // Pass 1: locate the stub section via the NON-LINEAR disk/runtime magic
    // (compute_disk_header_magic has no static 'VPCK' XOR constant — L7).
    for (WORD i = 0; i < num_sec; ++i) {
        const auto& s = sec[i];
        uint8_t* sec_base = base + s.VirtualAddress;
        size_t   sec_size = s.Misc.VirtualSize ? s.Misc.VirtualSize : s.SizeOfRawData;
        if (sec_size == 0) continue;

        bool is_stub_sec = false;
        bool runtime_handoff = false;
        uint64_t public_salt = 0;
        uint64_t hb = 0;
        if (sec_size >= sizeof(VPackHeader) && sec_size >= kScrTlsCbPair + 8) {
            // Runtime handoff state: EpStub wiped the master_seed field BEFORE OEP, so the
            // true public_salt lives in the Stage-2 stash at +0x8D0. It MUST be read FIRST
            // or the runtime magic can never be recomputed (this was the startup crash).
            uint64_t stashed = 0;
            std::memcpy(&stashed, sec_base + kScrPubSaltFinal, sizeof(uint64_t));
            if (stashed != 0) {
                hb = stashed ^ img_base_u64 ^ poison;
                if (*reinterpret_cast<const uint32_t*>(sec_base) == compute_disk_header_magic(hb)) {
                    is_stub_sec = true;
                    runtime_handoff = true;
                    public_salt = stashed;
                }
            }
            if (!is_stub_sec) {
                const auto* cand_hdr = reinterpret_cast<const VPackHeader*>(sec_base);
                if (cand_hdr->magic == compute_disk_header_magic(cand_hdr->master_seed)) {
                    is_stub_sec = true;
                    public_salt = cand_hdr->master_seed;
                    hb = public_salt ^ img_base_u64 ^ poison;
                }
            }
        }
        if (std::memcmp(s.Name, ".vpack", 6) == 0) {
            is_stub_sec = true;
            if (public_salt == 0) {
                public_salt = reinterpret_cast<const VPackHeader*>(sec_base)->master_seed;
                hb = public_salt ^ img_base_u64 ^ poison;
            }
        }

        if (is_stub_sec) {
            found_vpack = true;
            vpack_rva   = s.VirtualAddress;
            auto* vhdr = reinterpret_cast<VPackHeader*>(sec_base);

            // Only the runtime handoff carries hb-masked metadata the SDK can unmask.
            // (A disk-state header at main() would mask fields with the real seed, which
            // only the encrypted Stage 2 knows — nothing extractable, so skip safely.)
            if (runtime_handoff) {
                g_runtime_master_seed = public_salt; // PageVault seed (RAM-only, non-secret)

                vcode_rva  = vhdr->vcode_rva  ^ derive_header_field_mask(hb, kIdVcodeRva);
                vcode_size = vhdr->vcode_size ^ derive_header_field_mask(hb, kIdVcodeSize);
                vinit_rva  = vhdr->vinit_rva  ^ derive_header_field_mask(hb, kIdVinitRva);
                vinit_size = vhdr->vinit_size ^ derive_header_field_mask(hb, kIdVinitSize);

                // Live .vcode boot key (contains RDTSC ^ InterruptTime — unrecoverable offline)
                uint64_t masked_live = 0;
                std::memcpy(&masked_live, sec_base + kScrLiveVcodeKey, sizeof(uint64_t));
                live_boot_key = unmask_live_vcode_key(public_salt, masked_live);

                const uint32_t pdata_rva  = vhdr->orig_pdata_rva  ^ derive_header_field_mask(hb, kIdPdataRva);
                const uint32_t pdata_size = vhdr->orig_pdata_size ^ derive_header_field_mask(hb, kIdPdataSize);
                if (pdata_rva != 0 && pdata_size >= sizeof(RUNTIME_FUNCTION) && fn_add_ft.get()) {
                    auto* fn_table = reinterpret_cast<PRUNTIME_FUNCTION>(base + pdata_rva);
                    DWORD entry_count = pdata_size / sizeof(RUNTIME_FUNCTION);
                    fn_add_ft(fn_table, entry_count, reinterpret_cast<DWORD64>(base));
                }

                // Restore the ORIGINAL TLS callback array so DLL_THREAD_ATTACH/DETACH work.
                // Stage 2 publishes the neutralized cb0/cb1 RVAs in the plain handoff slot.
                uint32_t tls_cb0_rva = 0, tls_cb1_rva = 0;
                uint64_t tls_pair = 0;
                std::memcpy(&tls_pair, sec_base + kScrTlsCbPair, sizeof(uint64_t));
                tls_cb0_rva = static_cast<uint32_t>(tls_pair & 0xFFFFFFFFULL);
                tls_cb1_rva = static_cast<uint32_t>(tls_pair >> 32);
                const auto& tls_dir_entry = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
                if (tls_dir_entry.VirtualAddress != 0 && tls_dir_entry.Size >= sizeof(IMAGE_TLS_DIRECTORY64)) {
                    const auto* tls_dir = reinterpret_cast<const IMAGE_TLS_DIRECTORY64*>(base + tls_dir_entry.VirtualAddress);
                    if (tls_dir->AddressOfCallBacks > reinterpret_cast<uint64_t>(base)) {
                        auto* cb_slot = reinterpret_cast<uint64_t*>(tls_dir->AddressOfCallBacks);
                        DWORD old_p = 0;
                        if (fn_vprotect.get() && fn_vprotect(cb_slot, sizeof(uint64_t) * 2, PAGE_READWRITE, &old_p)) {
                            cb_slot[0] = (tls_cb0_rva != 0)
                                ? reinterpret_cast<uint64_t>(base + tls_cb0_rva)
                                : 0ULL;
                            cb_slot[1] = (tls_cb1_rva != 0)
                                ? reinterpret_cast<uint64_t>(base + tls_cb1_rva)
                                : 0ULL;
                            fn_vprotect(cb_slot, sizeof(uint64_t) * 2, old_p, &old_p);
                        }
                    }
                }
            }

            // Unlock, wipe 100% of the stub section (header, decoys, bridge, EpStub,
            // TlsStub, Stage 1), and re-seal to RX. The TLS slot above is restored, and a
            // 1-byte RET stays at TlsStub as a final safety net for any stale callback.
            if (fn_vprotect.get()) {
                DWORD old_prot = 0;
                fn_vprotect(sec_base, sec_size, PAGE_READWRITE, &old_prot);
            }
            crypto::secure_wipe(sec_base, sec_size, hb ^ poison);
            const uint32_t tls_ret_off = 0xA40;
            if (sec_size > tls_ret_off) {
                sec_base[tls_ret_off] = 0xC3; // ret
            }
            if (fn_vprotect.get()) {
                DWORD old_prot = 0;
                fn_vprotect(sec_base, sec_size, PAGE_EXECUTE_READ, &old_prot);
            }
        } else if (std::memcmp(s.Name, ".vcode", 6) == 0 && vcode_rva == 0) {
            vcode_rva  = s.VirtualAddress;
            vcode_size = static_cast<uint32_t>(sec_size);
        } else if (std::memcmp(s.Name, ".vinit", 6) == 0 && vinit_rva == 0) {
            vinit_rva  = s.VirtualAddress;
            vinit_size = static_cast<uint32_t>(sec_size);
        }
    }

    if (vinit_rva != 0 && vinit_size != 0) {
        g_vinit_base = base + vinit_rva;
        g_vinit_size = vinit_size;
    }

    // Pass 2: Restore strict non-writable permissions (L4): RX for code, RW for
    // writable data, R for read-only data. (Stage 2/1 unlock RWX only transiently.)
    for (WORD i = 0; i < num_sec; ++i) {
        const auto& s = sec[i];
        uint8_t* sec_base = base + s.VirtualAddress;
        size_t   sec_size = s.Misc.VirtualSize ? s.Misc.VirtualSize : s.SizeOfRawData;
        if (sec_size == 0 || s.VirtualAddress == vpack_rva) continue;

        // Skip protected code section if the JIT vault will lock & encrypt it below
        if ((flags & PROT_JIT_VCODE) && vcode_rva != 0 && s.VirtualAddress == vcode_rva) {
            continue;
        }

        if (fn_vprotect.get()) {
            DWORD old_prot = 0;
            if (s.Characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE)) {
                fn_vprotect(sec_base, sec_size, PAGE_EXECUTE_READ, &old_prot);
            } else if (s.Characteristics & IMAGE_SCN_MEM_WRITE) {
                fn_vprotect(sec_base, sec_size, PAGE_READWRITE, &old_prot);
            } else {
                fn_vprotect(sec_base, sec_size, PAGE_READONLY, &old_prot);
            }
        }
    }

    // Pass 3: Activate JIT Execute & Wipe Vault on the protected code section. When
    // packed, Stage 2 ALREADY re-encrypted it with the LIVE boot key (RDTSC-bound), so
    // init_jit_vcode_vault performs a single-pass register-only trans-encryption into
    // the runtime MBA stream without ever exposing plaintext in RAM.
    if ((flags & PROT_JIT_VCODE) && vcode_rva != 0 && vcode_size != 0) {
        const bool packed = (found_vpack && live_boot_key != 0);
        const uint64_t boot_key = packed ? live_boot_key : g_runtime_master_seed;
        antidump::init_jit_vcode_vault(base + vcode_rva, vcode_size, boot_key, packed);
    }

    return found_vpack;
}

} // namespace

RuntimeStatus Protector::initialize(uint32_t flags) noexcept {
    RuntimeStatus status{};
    status.active_flags = flags;
    status.packed_binary = finalize_vpack_section_in_memory(flags);

    // Cache module layout and baseline .text hash BEFORE erasing PE headers
    antidump::ModuleLayoutInfo layout{};
    if (antidump::query_module_layout(nullptr, layout)) {
        baseline_hash_ = layout.text_section_hash;
        status.text_baseline_hash = baseline_hash_;
    }

    if (flags & PROT_HIDE_THREAD) {
        antidebug::hide_current_thread();
    }

    if (flags & PROT_ANTI_DEBUG) {
        bool clear_hwbp = (flags & PROT_CLEAR_HWBP) != 0;
        status.initial_debug_report = antidebug::run_all_checks(clear_hwbp);
    }

    if (flags & PROT_TAMPER_IMAGE_SIZE) {
        antidump::tamper_peb_image_size(0x02000000u);
    }

    if ((flags & PROT_ANTI_DUMP) && !headers_erased_) {
        const bool keep_skeleton = (flags & PROT_PE_SKELETON) != 0;
        headers_erased_ = antidump::erase_pe_headers(nullptr, keep_skeleton);
    }

    // Wipe and lock the one-shot .vinit section to PAGE_NOACCESS
    if (g_vinit_base && g_vinit_size > 0) {
        antidump::wipe_and_lock_vinit_section(g_vinit_base, g_vinit_size);
        g_vinit_base = nullptr;
        g_vinit_size = 0;
    }

    // Activate Lazy Per-Page .text Vault
    if ((flags & PROT_PAGE_VAULT) && layout.text_section_base && layout.text_section_size > 0) {
        status.page_vault_active = vault::install(
            const_cast<void*>(layout.text_section_base),
            layout.text_section_size,
            nullptr,
            g_runtime_master_seed
        );
        if (status.page_vault_active) {
            baseline_hash_            = antidump::compute_text_integrity(nullptr);
            status.text_baseline_hash = baseline_hash_;
        }
    }

    if (flags & PROT_ANTI_VM) {
        status.initial_vm_report = antivm::run_all_vm_checks();
        if (status.initial_vm_report.is_virtual_machine()) {
            status.initial_debug_report.flags |= antidebug::THREAT_VIRTUAL_MACHINE;
        }
    }

    status.initialized = true;
    return status;
}

bool Protector::verify_environment(antidebug::DebugReport* out_report) noexcept {
    antidebug::DebugReport rep = antidebug::run_all_checks(true);

    if (baseline_hash_ != 0) {
        if (!antidump::verify_text_integrity(baseline_hash_, nullptr)) {
            rep.flags |= antidebug::THREAT_SOFTWARE_BREAKPOINT;
        }
    }

    if (!antidump::verify_vcode_integrity()) {
        rep.flags |= antidebug::THREAT_VCODE_TAMPERED;
    }

    if (out_report) {
        *out_report = rep;
    }
    return !rep.detected();
}

} // namespace vpack
