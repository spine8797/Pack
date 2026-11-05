#include "vpack/vpack.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstring>

namespace vpack {

uint64_t Protector::baseline_hash_ = 0;
bool     Protector::headers_erased_ = false;

namespace {

uint8_t* g_vinit_base = nullptr;
size_t   g_vinit_size = 0;

// Registers decrypted .pdata unwind table, initializes the JIT Execute & Wipe vault for .vcode (.sbl1),
// wipes the entire .vpack section (Stage 1, Synthetic Imports, VPackHeader) leaving only a 1-byte RET
// at TlsStub, and restores strict RX / R section permissions so zero RWX pages remain in process memory!
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
    uint32_t vcode_rva   = 0;
    uint32_t vcode_size  = 0;
    uint32_t vinit_rva   = 0;
    uint32_t vinit_size  = 0;
    uint64_t master_seed = 0xB7E193C58A2F4D91ULL;

    const IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    const WORD num_sec = nt->FileHeader.NumberOfSections;

    // Pass 1: Extract VPackHeader metadata & locate .vcode / .vinit (even if masqueraded as .sbl*)
    for (WORD i = 0; i < num_sec; ++i) {
        const auto& s = sec[i];
        uint8_t* sec_base = base + s.VirtualAddress;
        size_t   sec_size = s.Misc.VirtualSize ? s.Misc.VirtualSize : s.SizeOfRawData;
        if (sec_size == 0) continue;

        if (std::memcmp(s.Name, ".vpack", 6) == 0) {
            found_vpack = true;
            auto* vhdr = reinterpret_cast<VPackHeader*>(sec_base);
            uint32_t seed_lo = static_cast<uint32_t>(vhdr->master_seed & 0xFFFFFFFFULL);
            uint32_t seed_hi = static_cast<uint32_t>((vhdr->master_seed >> 32) & 0xFFFFFFFFULL);
            uint32_t expected_magic = (seed_lo ^ 0xFFFFFFFFu) ^ VPACK_MAGIC;
            if (vhdr->magic == expected_magic) {
                master_seed = vhdr->master_seed;
                vcode_rva   = vhdr->vcode_rva ^ seed_lo;
                vcode_size  = vhdr->vcode_size ^ seed_hi;
                vinit_rva   = vhdr->vinit_rva ^ seed_lo;
                vinit_size  = vhdr->vinit_size ^ seed_hi;

                const uint32_t pdata_rva  = vhdr->orig_pdata_rva ^ seed_lo;
                const uint32_t pdata_size = vhdr->orig_pdata_size ^ seed_hi;
                if (pdata_rva != 0 && pdata_size >= sizeof(RUNTIME_FUNCTION) && fn_add_ft.get()) {
                    auto* fn_table = reinterpret_cast<PRUNTIME_FUNCTION>(base + pdata_rva);
                    DWORD entry_count = pdata_size / sizeof(RUNTIME_FUNCTION);
                    fn_add_ft(fn_table, entry_count, reinterpret_cast<DWORD64>(base));
                }
            }

            // Wipe 100% of .vpack (VPackHeader, Synthetic Imports "LoadLibraryA"/"GetProcAddress",
            // EP Stub, Stage 1, and Stage 2), leaving only a 1-byte RET (0xC3) at kTlsStubOffset (0xA40)
            // so DLL_PROCESS_DETACH exits cleanly!
            crypto::secure_wipe(sec_base, sec_size, master_seed);
            if (sec_size > 0xA40) {
                sec_base[0xA40] = 0xC3; // ret
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

    // Pass 2: Restore strict non-writable permissions on code (.text) and read-only (.rdata, .pdata, .xdata, .idata)
    for (WORD i = 0; i < num_sec; ++i) {
        const auto& s = sec[i];
        uint8_t* sec_base = base + s.VirtualAddress;
        size_t   sec_size = s.Misc.VirtualSize ? s.Misc.VirtualSize : s.SizeOfRawData;
        if (sec_size == 0 || std::memcmp(s.Name, ".vpack", 6) == 0) continue;

        // Skip .vcode here if JIT vault will lock & encrypt it below
        if ((flags & PROT_JIT_VCODE) && vcode_rva != 0 && s.VirtualAddress == vcode_rva) {
            continue;
        }

        if (fn_vprotect.get()) {
            DWORD old_prot = 0;
            const bool is_vinit_section =
                vinit_rva != 0 && s.VirtualAddress == vinit_rva;
            const bool executable_section =
                (s.Characteristics & IMAGE_SCN_MEM_EXECUTE) || is_vinit_section;

            if (executable_section) {
                // Convert RWX -> RX (PAGE_EXECUTE_READ)
                fn_vprotect(sec_base, sec_size, PAGE_EXECUTE_READ, &old_prot);
            } else if (std::memcmp(s.Name, ".rdata", 6) == 0 ||
                       std::memcmp(s.Name, ".sbl", 4) == 0) {
                // Convert RW -> R (PAGE_READONLY)
                fn_vprotect(sec_base, sec_size, PAGE_READONLY, &old_prot);
            }
        }
    }

    // Pass 3: Activate JIT Execute & Wipe Vault on .vcode (.sbl1) so protected functions and
    // VM handlers remain encrypted & non-executable (PAGE_READONLY) at rest in RAM!
    // Note: When packed (found_vpack == true), Stage 2 ALREADY re-encrypted .vcode before OEP
    // using vcode_boot_key, so init_jit_vcode_vault performs a single-pass register-only
    // trans-encryption without ever exposing plaintext .vcode in RAM!
    if ((flags & PROT_JIT_VCODE) && vcode_rva != 0 && vcode_size != 0) {
        const uint64_t morph_key      = crypto::poly_permute_64(master_seed, 0xB981C7E3D52A9F47ULL);
        const uint64_t vcode_boot_key = found_vpack
            ? (master_seed ^ morph_key ^ 0xE19B83C5D72F4A93ULL)
            : master_seed;
        antidump::init_jit_vcode_vault(base + vcode_rva, vcode_size, vcode_boot_key, found_vpack);
    }

    return found_vpack;
}

} // namespace

RuntimeStatus Protector::initialize(uint32_t flags) noexcept {
    RuntimeStatus status{};
    status.active_flags = flags;
    status.packed_binary = finalize_vpack_section_in_memory(flags);

    // Cache module layout, baseline .text hash, and loaded DLL list BEFORE erasing PE headers
    antidump::ModuleLayoutInfo layout{};
    if (antidump::query_module_layout(nullptr, layout)) {
        baseline_hash_ = layout.text_section_hash;
        status.text_baseline_hash = baseline_hash_;
    }
    antidump::capture_module_baseline();

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
        headers_erased_ = antidump::erase_pe_headers(nullptr);
    }

    // Wipe and lock the one-shot .vinit section (finalize_vpack_section_in_memory, init_jit_vcode_vault,
    // erase_pe_headers, tamper_peb_image_size, capture_module_baseline) to PAGE_NOACCESS (?? ??)!
    if (g_vinit_base && g_vinit_size > 0) {
        antidump::wipe_and_lock_vinit_section(g_vinit_base, g_vinit_size);
        g_vinit_base = nullptr;
        g_vinit_size = 0;
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

    if (antidump::detect_injected_module(&rep.injected_module_base, rep.injected_module_name, sizeof(rep.injected_module_name))) {
        rep.flags |= antidebug::THREAT_DLL_INJECTED;
    }

    if (out_report) {
        *out_report = rep;
    }
    return !rep.detected();
}

} // namespace vpack
