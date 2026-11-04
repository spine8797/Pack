#include "vpack/anti_dump.h"
#include "vpack/crypto.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <intrin.h>
#include <cstring>

namespace vpack::antidump {

namespace {

struct UnicodeStringT {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
};

struct PebLdrDataT {
    ULONG      Length;
    BOOLEAN    Initialized;
    PVOID      SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
};

struct LdrDataTableEntryLoadOrderT {
    LIST_ENTRY     InLoadOrderLinks;
    LIST_ENTRY     InMemoryOrderLinks;
    LIST_ENTRY     InInitializationOrderLinks;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UnicodeStringT FullDllName;
    UnicodeStringT BaseDllName;
};

VPACK_FORCEINLINE uint8_t* get_peb_mutable() noexcept {
#if defined(_M_X64) || defined(__x86_64__)
    return reinterpret_cast<uint8_t*>(__readgsqword(0x60));
#elif defined(_M_IX86) || defined(__i386__)
    return reinterpret_cast<uint8_t*>(__readfsdword(0x30));
#else
    return nullptr;
#endif
}

uint64_t hash_unicode_ci(const wchar_t* buf, size_t char_len) noexcept {
    uint64_t hash = 0xCBF29CE484222325ULL;
    for (size_t i = 0; i < char_len; ++i) {
        wchar_t wc = buf[i];
        if (wc >= L'A' && wc <= L'Z') {
            wc = static_cast<wchar_t>(wc + (L'a' - L'A'));
        }
        hash ^= static_cast<uint8_t>(wc & 0xFF);
        hash *= 0x100000001B3ULL;
    }
    return hash;
}

ModuleLayoutInfo g_cached_main_layout{};
bool             g_has_cached_layout = false;

constexpr size_t kMaxBaselineModules = 128;
void*            g_baseline_modules[kMaxBaselineModules]{};
size_t           g_baseline_module_count = 0;

} // namespace

bool query_module_layout(void* module_base, ModuleLayoutInfo& out_info) noexcept {
    if (!module_base) {
        module_base = reinterpret_cast<void*>(GetModuleHandleW(nullptr));
    }
    if (!module_base) return false;

    if (g_has_cached_layout && g_cached_main_layout.base_address == module_base) {
        out_info = g_cached_main_layout;
        return true;
    }

    auto* base = static_cast<const uint8_t*>(module_base);
    auto* dos  = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }

    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }

    out_info.base_address = module_base;
    out_info.original_size_of_image = nt->OptionalHeader.SizeOfImage;
    out_info.text_section_base = nullptr;
    out_info.text_section_size = 0;
    out_info.text_section_hash = 0;

    const IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (std::memcmp(sec->Name, ".text", 5) == 0 ||
            (sec->Characteristics & IMAGE_SCN_CNT_CODE) != 0) {
            out_info.text_section_base = base + sec->VirtualAddress;
            out_info.text_section_size = sec->Misc.VirtualSize ? sec->Misc.VirtualSize : sec->SizeOfRawData;
            out_info.text_section_hash = crypto::fnv1a_64(out_info.text_section_base, out_info.text_section_size);
            break;
        }
    }

    if (module_base == reinterpret_cast<void*>(GetModuleHandleW(nullptr))) {
        g_cached_main_layout = out_info;
        g_has_cached_layout = true;
    }

    return out_info.text_section_base != nullptr;
}

uint64_t compute_text_integrity(void* module_base) noexcept {
    ModuleLayoutInfo info{};
    if (!query_module_layout(module_base, info) || !info.text_section_base || info.text_section_size == 0) {
        return 0;
    }
    return crypto::fnv1a_64(info.text_section_base, info.text_section_size);
}

bool verify_text_integrity(uint64_t expected_hash, void* module_base) noexcept {
    if (expected_hash == 0) return false;
    return compute_text_integrity(module_base) == expected_hash;
}

bool erase_pe_headers(void* module_base) noexcept {
    if (!module_base) {
        module_base = reinterpret_cast<void*>(GetModuleHandleW(nullptr));
    }
    if (!module_base) return false;

    ModuleLayoutInfo unused{};
    query_module_layout(module_base, unused);

    auto* base = static_cast<uint8_t*>(module_base);
    auto* dos  = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }

    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }

    DWORD header_size = nt->OptionalHeader.SizeOfHeaders;
    if (header_size == 0 || header_size > 0x10000) {
        header_size = 0x1000;
    }

    DWORD old_protect = 0;
    using FnVirtualProtect = BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD);
    static auto fn_vprotect = VPACK_IMPORT(FnVirtualProtect, "kernel32.dll", "VirtualProtect");
    if (!fn_vprotect.get() || !fn_vprotect(base, header_size, PAGE_READWRITE, &old_protect)) {
        return false;
    }

    // Wipe DOS header, DOS stub, NT Signature, FileHeader, and Section headers
    uint32_t lfanew = static_cast<uint32_t>(dos->e_lfanew);
    IMAGE_SECTION_HEADER* first_sec = IMAGE_FIRST_SECTION(nt);
    WORD num_sections = nt->FileHeader.NumberOfSections;

    std::memset(first_sec, 0, sizeof(IMAGE_SECTION_HEADER) * num_sections);
    nt->Signature = 0;
    nt->FileHeader.Machine = 0;
    nt->FileHeader.NumberOfSections = 0;
    nt->FileHeader.TimeDateStamp = 0;
    std::memset(base, 0, (lfanew < header_size) ? lfanew : sizeof(IMAGE_DOS_HEADER));

    DWORD dummy = 0;
    fn_vprotect(base, header_size, old_protect, &dummy);
    return true;
}

bool tamper_peb_image_size(uint32_t fake_size_delta) noexcept {
    uint8_t* peb = get_peb_mutable();
    if (!peb) return false;

#if defined(_M_X64) || defined(__x86_64__)
    auto* ldr = *reinterpret_cast<PebLdrDataT**>(peb + 0x18);
#else
    auto* ldr = *reinterpret_cast<PebLdrDataT**>(peb + 0x0C);
#endif
    if (!ldr) return false;

    LIST_ENTRY* head = &ldr->InLoadOrderModuleList;
    LIST_ENTRY* curr = head->Flink;
    if (!curr || curr == head) return false;

    auto* entry = reinterpret_cast<LdrDataTableEntryLoadOrderT*>(curr);
    entry->SizeOfImage += fake_size_delta;
    return true;
}

uint32_t capture_module_baseline() noexcept {
    g_baseline_module_count = 0;
    uint8_t* peb = get_peb_mutable();
    if (!peb) return 0;

#if defined(_M_X64) || defined(__x86_64__)
    auto* ldr = *reinterpret_cast<PebLdrDataT**>(peb + 0x18);
#else
    auto* ldr = *reinterpret_cast<PebLdrDataT**>(peb + 0x0C);
#endif
    if (!ldr) return 0;

    LIST_ENTRY* head = &ldr->InLoadOrderModuleList;
    for (LIST_ENTRY* it = head->Flink; it && it != head; it = it->Flink) {
        auto* entry = reinterpret_cast<LdrDataTableEntryLoadOrderT*>(it);
        if (entry->DllBase && g_baseline_module_count < kMaxBaselineModules) {
            g_baseline_modules[g_baseline_module_count++] = entry->DllBase;
        }
    }
    return static_cast<uint32_t>(g_baseline_module_count);
}

bool detect_injected_module(void** out_base, char* out_name, size_t max_len) noexcept {
    if (g_baseline_module_count == 0) return false;
    uint8_t* peb = get_peb_mutable();
    if (!peb) return false;

#if defined(_M_X64) || defined(__x86_64__)
    auto* ldr = *reinterpret_cast<PebLdrDataT**>(peb + 0x18);
#else
    auto* ldr = *reinterpret_cast<PebLdrDataT**>(peb + 0x0C);
#endif
    if (!ldr) return false;

    LIST_ENTRY* head = &ldr->InLoadOrderModuleList;
    for (LIST_ENTRY* it = head->Flink; it && it != head; it = it->Flink) {
        auto* entry = reinterpret_cast<LdrDataTableEntryLoadOrderT*>(it);
        if (!entry->DllBase) continue;

        bool known = false;
        for (size_t i = 0; i < g_baseline_module_count; ++i) {
            if (g_baseline_modules[i] == entry->DllBase) {
                known = true;
                break;
            }
        }

        if (!known) {
            if (out_base) *out_base = entry->DllBase;
            if (out_name && max_len > 0) {
                size_t chars = entry->BaseDllName.Length / sizeof(wchar_t);
                size_t copy_len = (chars < max_len - 1) ? chars : (max_len - 1);
                for (size_t c = 0; c < copy_len; ++c) {
                    out_name[c] = static_cast<char>(entry->BaseDllName.Buffer[c] & 0xFF);
                }
                out_name[copy_len] = '\0';
            }
            return true;
        }
    }
    return false;
}

void* resolve_export_by_hash(uint64_t module_hash_ci, uint64_t proc_hash_ci) noexcept {
    uint8_t* peb = get_peb_mutable();
    if (!peb) return nullptr;

#if defined(_M_X64) || defined(__x86_64__)
    auto* ldr = *reinterpret_cast<PebLdrDataT**>(peb + 0x18);
#else
    auto* ldr = *reinterpret_cast<PebLdrDataT**>(peb + 0x0C);
#endif
    if (!ldr) return nullptr;

    LIST_ENTRY* head = &ldr->InLoadOrderModuleList;
    for (LIST_ENTRY* it = head->Flink; it && it != head; it = it->Flink) {
        auto* entry = reinterpret_cast<LdrDataTableEntryLoadOrderT*>(it);
        if (!entry->DllBase || !entry->BaseDllName.Buffer || entry->BaseDllName.Length == 0) {
            continue;
        }

        size_t char_count = entry->BaseDllName.Length / sizeof(wchar_t);
        if (hash_unicode_ci(entry->BaseDllName.Buffer, char_count) != module_hash_ci) {
            continue;
        }

        const auto* mod_base = static_cast<const uint8_t*>(entry->DllBase);
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(mod_base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) continue;

        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(mod_base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) continue;

        const auto& exp_dir_entry = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (exp_dir_entry.VirtualAddress == 0 || exp_dir_entry.Size == 0) continue;

        const auto* exp_dir = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(mod_base + exp_dir_entry.VirtualAddress);
        const auto* names   = reinterpret_cast<const DWORD*>(mod_base + exp_dir->AddressOfNames);
        const auto* funcs   = reinterpret_cast<const DWORD*>(mod_base + exp_dir->AddressOfFunctions);
        const auto* ords    = reinterpret_cast<const WORD*>(mod_base + exp_dir->AddressOfNameOrdinals);

        for (DWORD i = 0; i < exp_dir->NumberOfNames; ++i) {
            const char* fn_name = reinterpret_cast<const char*>(mod_base + names[i]);
            if (crypto::fnv1a_64_ci(fn_name) == proc_hash_ci) {
                WORD ordinal = ords[i];
                DWORD func_rva = funcs[ordinal];

                // Check if forwarded export
                if (func_rva >= exp_dir_entry.VirtualAddress &&
                    func_rva < exp_dir_entry.VirtualAddress + exp_dir_entry.Size) {
                    return reinterpret_cast<void*>(GetProcAddress(
                        reinterpret_cast<HMODULE>(entry->DllBase),
                        fn_name
                    ));
                }
                return const_cast<uint8_t*>(mod_base + func_rva);
            }
        }
    }

    return nullptr;
}

} // namespace vpack::antidump
