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

// Registers decrypted .pdata unwind table, wipes the entire .vpack section (Stage 1, Synthetic Imports,
// VPackHeader) leaving only a 1-byte RET at TlsStub, and restores strict RX / R section permissions
// so zero RWX pages remain in process memory!
bool finalize_vpack_section_in_memory() noexcept {
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

    bool found_vpack = false;
    const IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    const WORD num_sec = nt->FileHeader.NumberOfSections;

    for (WORD i = 0; i < num_sec; ++i, ++sec) {
        uint8_t* sec_base = base + sec->VirtualAddress;
        size_t   sec_size = sec->Misc.VirtualSize ? sec->Misc.VirtualSize : sec->SizeOfRawData;
        if (sec_size == 0) continue;

        if (std::memcmp(sec->Name, ".vpack", 6) == 0) {
            found_vpack = true;
            auto* vhdr = reinterpret_cast<VPackHeader*>(sec_base);
            uint32_t expected_magic = static_cast<uint32_t>((vhdr->master_seed & 0xFFFFFFFFULL) ^ 0xFFFFFFFFULL) ^ VPACK_MAGIC;
            if (vhdr->magic == expected_magic) {
                if (vhdr->orig_pdata_rva != 0 && vhdr->orig_pdata_size >= sizeof(RUNTIME_FUNCTION) && fn_add_ft.get()) {
                    auto* fn_table = reinterpret_cast<PRUNTIME_FUNCTION>(base + vhdr->orig_pdata_rva);
                    DWORD entry_count = vhdr->orig_pdata_size / sizeof(RUNTIME_FUNCTION);
                    fn_add_ft(fn_table, entry_count, reinterpret_cast<DWORD64>(base));
                }
            }

            // Wipe 100% of .vpack (VPackHeader, Synthetic Imports "LoadLibraryA"/"GetProcAddress",
            // EP Stub, Stage 1, and Stage 2), leaving only a 1-byte RET (0xC3) at kTlsStubOffset (0xA40)
            // so DLL_PROCESS_DETACH exits cleanly!
            std::memset(sec_base, 0, sec_size);
            if (sec_size > 0xA40) {
                sec_base[0xA40] = 0xC3; // ret
            }

            if (fn_vprotect.get()) {
                DWORD old_prot = 0;
                fn_vprotect(sec_base, sec_size, PAGE_EXECUTE_READ, &old_prot);
            }
            continue;
        }

        // Restore strict non-writable permissions on code (.text, .sbl1) and read-only (.rdata, .pdata, .xdata, .idata)
        if (fn_vprotect.get()) {
            DWORD old_prot = 0;
            if (sec->Characteristics & IMAGE_SCN_CNT_CODE) {
                // Convert RWX -> RX (PAGE_EXECUTE_READ)
                fn_vprotect(sec_base, sec_size, PAGE_EXECUTE_READ, &old_prot);
            } else if (std::memcmp(sec->Name, ".rdata", 6) == 0 ||
                       std::memcmp(sec->Name, ".sbl5", 5) == 0 ||
                       std::memcmp(sec->Name, ".sbl6", 5) == 0 ||
                       std::memcmp(sec->Name, ".sbl8", 5) == 0) {
                // Convert RW -> R (PAGE_READONLY)
                fn_vprotect(sec_base, sec_size, PAGE_READONLY, &old_prot);
            }
        }
    }

    return found_vpack;
}

} // namespace

RuntimeStatus Protector::initialize(uint32_t flags) noexcept {
    RuntimeStatus status{};
    status.active_flags = flags;
    status.packed_binary = finalize_vpack_section_in_memory();

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

    if (antidump::detect_injected_module(&rep.injected_module_base, rep.injected_module_name, sizeof(rep.injected_module_name))) {
        rep.flags |= antidebug::THREAT_DLL_INJECTED;
    }

    if (out_report) {
        *out_report = rep;
    }
    return !rep.detected();
}

} // namespace vpack
