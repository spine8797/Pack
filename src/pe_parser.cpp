#include "vpack/pe_parser.h"
#include "vpack/crypto.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <fstream>
#include <cstring>
#include <chrono>

namespace vpack::pe {

namespace {

constexpr uint32_t align_up(uint32_t val, uint32_t alignment) noexcept {
    if (alignment == 0) return val;
    return (val + alignment - 1) & ~(alignment - 1);
}

constexpr uint64_t rotr64(uint64_t x, int n) noexcept {
    return (x >> n) | (x << (64 - n));
}

void stub_stream_xor(uint8_t* data, size_t size, uint64_t key) noexcept {
    uint64_t r10 = key;
    for (size_t i = 0; i < size; ++i) {
        r10 = rotr64(r10, 13) + 0x9E3779B97F4A7C15ULL;
        data[i] ^= static_cast<uint8_t>(r10 & 0xFF);
    }
}

constexpr uint32_t kSynthImportOffset = 0x900;
constexpr uint32_t kSynthIltOffset    = 0x930;
constexpr uint32_t kSynthIatOffset    = 0x948;
constexpr uint32_t kSynthDllNameOff   = 0x960;
constexpr uint32_t kSynthFnLoadLibOff = 0x970;
constexpr uint32_t kSynthFnGetProcOff = 0x980;

constexpr uint32_t kEpStubOffset      = 0xA00;
constexpr uint32_t kTlsStubOffset     = 0xA40;
constexpr uint32_t kStage1Offset      = 0xA80;
constexpr uint32_t kStage2Offset      = 0xB00;

// Builds the complete 2-Stage Self-Decrypting & Self-Wiping .vpack section payload:
//   [0x000 .. 0x8F4) : Masked VPackHeader
//   [0x900 .. 0x998) : Synthetic Import Table (imports ONLY LoadLibraryA & GetProcAddress)
//   [0xA00 .. 0xA40) : EntryPoint Stub (with opaque predicate anti-disassembly)
//   [0xA40 .. 0xA80) : TLS Callback Stub (with opaque predicate anti-disassembly)
//   [0xA80 .. 0xB00) : Stage 1 Bootstrap (decrypts Stage 2 using NtGlobalFlag, calls it, then wipes Stage 2)
//   [0xB00 .. end)   : Stage 2 Encrypted Unpacker + Dynamic IAT Resolver (encrypted on disk!)
std::vector<uint8_t> build_vpack_section_payload(const VPackHeader& vhdr, uint32_t vpack_sec_rva, bool enable_anti_debug) {
    std::vector<uint8_t> sec(kStage2Offset, 0);

    // Fill slack space between header and stubs with pseudo-random noise to defeat visual boundary scanning
    uint64_t noise = vhdr.master_seed ^ 0xF00DBAADBEEF1337ULL;
    for (size_t i = sizeof(VPackHeader); i < kStage2Offset; ++i) {
        noise = rotr64(noise, 11) + 0x9E3779B97F4A7C15ULL;
        sec[i] = static_cast<uint8_t>(noise & 0xFF);
    }

    std::memcpy(sec.data(), &vhdr, sizeof(VPackHeader));

    // Populate Synthetic 2-Function Import Table at kSynthImportOffset (0x900)
    std::memset(sec.data() + kSynthImportOffset, 0, 0xA0);
    auto* synth_desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(sec.data() + kSynthImportOffset);
    synth_desc[0].OriginalFirstThunk = vpack_sec_rva + kSynthIltOffset;
    synth_desc[0].TimeDateStamp      = 0;
    synth_desc[0].ForwarderChain     = 0;
    synth_desc[0].Name               = vpack_sec_rva + kSynthDllNameOff;
    synth_desc[0].FirstThunk         = vpack_sec_rva + kSynthIatOffset;

    auto* synth_ilt = reinterpret_cast<uint64_t*>(sec.data() + kSynthIltOffset);
    synth_ilt[0] = vpack_sec_rva + kSynthFnLoadLibOff;
    synth_ilt[1] = vpack_sec_rva + kSynthFnGetProcOff;
    synth_ilt[2] = 0;

    auto* synth_iat = reinterpret_cast<uint64_t*>(sec.data() + kSynthIatOffset);
    synth_iat[0] = vpack_sec_rva + kSynthFnLoadLibOff;
    synth_iat[1] = vpack_sec_rva + kSynthFnGetProcOff;
    synth_iat[2] = 0;

    std::memcpy(sec.data() + kSynthDllNameOff, "KERNEL32.dll", 13);
    std::memcpy(sec.data() + kSynthFnLoadLibOff + 2, "LoadLibraryA", 13);
    std::memcpy(sec.data() + kSynthFnGetProcOff + 2, "GetProcAddress", 15);

    auto write_i32 = [](std::vector<uint8_t>& buf, size_t pos, int32_t val) {
        for (int i = 0; i < 4; ++i) {
            buf[pos + i] = static_cast<uint8_t>((val >> (i * 8)) & 0xFF);
        }
    };

    // -------------------------------------------------------------------------
    // 1. EntryPoint Stub at kEpStubOffset (0x200)
    // -------------------------------------------------------------------------
    {
        std::vector<uint8_t> ep;
        auto emit = [&](std::initializer_list<uint8_t> b) { ep.insert(ep.end(), b.begin(), b.end()); };

        // Anti-disassembly opaque predicate (push rax; xor eax, eax; jz +2; db 0xE8, 0x90; pop rax)
        emit({0x50, 0x31, 0xC0, 0x74, 0x02, 0xE8, 0x90, 0x58});

        // call Stage 1 (at kStage1Offset)
        int32_t rel_call = static_cast<int32_t>(kStage1Offset) -
                           static_cast<int32_t>(kEpStubOffset + ep.size() + 5);
        emit({0xE8, 0, 0, 0, 0});
        write_i32(ep, ep.size() - 4, rel_call);

        // lea rax, [rip + disp_to_header] (offset 0x000)
        int32_t disp_hdr = -static_cast<int32_t>(kEpStubOffset + ep.size() + 7);
        emit({0x48, 0x8D, 0x05, 0, 0, 0, 0});
        write_i32(ep, ep.size() - 4, disp_hdr);

        // mov r11, gs:[0x60] (PEB)
        emit({0x65, 0x4C, 0x8B, 0x1C, 0x25, 0x60, 0x00, 0x00, 0x00});
        // mov r11, [r11 + 0x10] (ImageBase)
        emit({0x4D, 0x8B, 0x5B, 0x10});
        // mov r10d, dword ptr [rax + 0x10] (low32(master_seed))
        emit({0x44, 0x8B, 0x50, 0x10});
        // mov eax, dword ptr [rax + 0x0C] (masked original_entry_rva)
        emit({0x8B, 0x40, 0x0C});
        // xor eax, r10d (unmask original_entry_rva)
        emit({0x44, 0x31, 0xD0});
        // add rax, r11 (ImageBase + original_entry_rva)
        emit({0x4C, 0x01, 0xD8});
        // jmp rax
        emit({0xFF, 0xE0});

        std::memcpy(sec.data() + kEpStubOffset, ep.data(), ep.size());
    }

    // -------------------------------------------------------------------------
    // 2. TLS Callback Stub at kTlsStubOffset (0x240)
    // -------------------------------------------------------------------------
    {
        std::vector<uint8_t> tls;
        auto emit = [&](std::initializer_list<uint8_t> b) { tls.insert(tls.end(), b.begin(), b.end()); };

        // Anti-disassembly opaque predicate (push rax; xor eax, eax; jz +2; db 0xE9, 0x90; pop rax)
        emit({0x50, 0x31, 0xC0, 0x74, 0x02, 0xE9, 0x90, 0x58});

        // call Stage 1 (at kStage1Offset)
        int32_t rel_call = static_cast<int32_t>(kStage1Offset) -
                           static_cast<int32_t>(kTlsStubOffset + tls.size() + 5);
        emit({0xE8, 0, 0, 0, 0});
        write_i32(tls, tls.size() - 4, rel_call);

        // lea rax, [rip + disp_to_header] (offset 0x000)
        int32_t disp_hdr = -static_cast<int32_t>(kTlsStubOffset + tls.size() + 7);
        emit({0x48, 0x8D, 0x05, 0, 0, 0, 0});
        write_i32(tls, tls.size() - 4, disp_hdr);

        // mov r11, gs:[0x60] (PEB)
        emit({0x65, 0x4C, 0x8B, 0x1C, 0x25, 0x60, 0x00, 0x00, 0x00});
        // mov r11, [r11 + 0x10] (ImageBase)
        emit({0x4D, 0x8B, 0x5B, 0x10});
        // mov r10d, dword ptr [rax + 0x14] (high32(master_seed))
        emit({0x44, 0x8B, 0x50, 0x14});
        // mov eax, dword ptr [rax + 0x20] (masked orig_tls_callback_rva)
        emit({0x8B, 0x40, 0x20});
        // xor eax, r10d (unmask orig_tls_callback_rva)
        emit({0x44, 0x31, 0xD0});
        // test eax, eax
        emit({0x85, 0xC0});
        // jz +5 (to ret)
        emit({0x74, 0x05});
        // add rax, r11
        emit({0x4C, 0x01, 0xD8});
        // jmp rax
        emit({0xFF, 0xE0});
        // ret
        emit({0xC3});

        std::memcpy(sec.data() + kTlsStubOffset, tls.data(), tls.size());
    }

    // -------------------------------------------------------------------------
    // 3. Stage 2 Encrypted Unpacker Engine (placed at kStage2Offset = 0x300)
    // -------------------------------------------------------------------------
    std::vector<uint8_t> stage2;
    {
        auto emit = [&](std::initializer_list<uint8_t> b) { stage2.insert(stage2.end(), b.begin(), b.end()); };

        // Immediately zero region_count so decryption is strictly one-shot:
        // mov word ptr [rbx + 0x06], 0
        emit({0x66, 0xC7, 0x43, 0x06, 0x00, 0x00});

        // mov rax, gs:[0x60] (PEB)
        emit({0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00});
        // mov rsi, [rax + 0x10] (ImageBase)
        emit({0x48, 0x8B, 0x70, 0x10});

        // Branchless Anti-Debug key perturbation in r9 (PEB->BeingDebugged + KUSER_SHARED_DATA->KdDebuggerEnabled)
        if (enable_anti_debug) {
            emit({0x0F, 0xB6, 0x40, 0x02});             // movzx eax, byte ptr [rax + 0x02] (PEB->BeingDebugged)
            emit({0x48, 0xC1, 0xE0, 0x0D});             // shl rax, 13
            emit({0x49, 0x89, 0xC1});                   // mov r9, rax
            emit({0x0F, 0xB6, 0x04, 0x25, 0xD4, 0x02, 0xFE, 0x7F}); // movzx eax, byte ptr [0x7FFE02D4] (KdDebuggerEnabled)
            emit({0x83, 0xE0, 0x01});                   // and eax, 1
            emit({0x48, 0xC1, 0xE0, 0x11});             // shl rax, 17
            emit({0x49, 0x31, 0xC1});                   // xor r9, rax
        } else {
            emit({0x4D, 0x31, 0xC9});                   // xor r9, r9
        }

        // lea r8, [rbx + 0x30] (&regions[0])
        emit({0x4C, 0x8D, 0x43, 0x30});

        const size_t lbl_region_loop = stage2.size();
        emit({0x85, 0xD2}); // test edx, edx
        const size_t jz_regions_done_pos = stage2.size();
        emit({0x74, 0x00}); // jz lbl_regions_done

        emit({0x41, 0x8B, 0x48, 0x04}); // mov ecx, dword ptr [r8 + 0x04] (masked region.size)
        emit({0x33, 0x4B, 0x14});       // xor ecx, dword ptr [rbx + 0x14] (unmask with high32(master_seed))
        emit({0x85, 0xC9});             // test ecx, ecx
        const size_t jz_next_region_pos = stage2.size();
        emit({0x74, 0x00});             // jz lbl_next_region

        emit({0x41, 0x8B, 0x00});       // mov eax, dword ptr [r8 + 0x00] (masked region.rva)
        emit({0x33, 0x43, 0x10});       // xor eax, dword ptr [rbx + 0x10] (unmask with low32(master_seed))
        emit({0x48, 0x8D, 0x3C, 0x06}); // lea rdi, [rsi + rax]
        emit({0x4D, 0x8B, 0x50, 0x08}); // mov r10, qword ptr [r8 + 0x08] (region.key)
        emit({0x4D, 0x31, 0xCA});       // xor r10, r9
        emit({0x49, 0xBB, 0x15, 0x7C, 0x4A, 0x7F, 0xB9, 0x79, 0x37, 0x9E}); // mov r11, 0x9E3779B97F4A7C15

        const size_t lbl_byte_loop = stage2.size();
        emit({0x49, 0xC1, 0xCA, 0x0D}); // ror r10, 13
        emit({0x4D, 0x01, 0xDA});       // add r10, r11
        emit({0x44, 0x88, 0xD0});       // mov al, r10b
        emit({0x30, 0x07});             // xor byte ptr [rdi], al
        emit({0x48, 0xFF, 0xC7});       // inc rdi
        emit({0xFF, 0xC9});             // dec ecx
        int8_t rel_byte_loop = static_cast<int8_t>(static_cast<intptr_t>(lbl_byte_loop) - static_cast<intptr_t>(stage2.size() + 2));
        emit({0x75, static_cast<uint8_t>(rel_byte_loop)});

        // Wipe region.key in memory: mov qword ptr [r8 + 0x08], 0
        emit({0x49, 0xC7, 0x40, 0x08, 0x00, 0x00, 0x00, 0x00});

        const size_t lbl_next_region = stage2.size();
        stage2[jz_next_region_pos + 1] = static_cast<uint8_t>(lbl_next_region - (jz_next_region_pos + 2));

        emit({0x49, 0x83, 0xC0, 0x18}); // add r8, 0x18
        emit({0xFF, 0xCA});             // dec edx
        int8_t rel_region_loop = static_cast<int8_t>(static_cast<intptr_t>(lbl_region_loop) - static_cast<intptr_t>(stage2.size() + 2));
        emit({0xEB, static_cast<uint8_t>(rel_region_loop)});

        const size_t lbl_regions_done = stage2.size();
        stage2[jz_regions_done_pos + 1] = static_cast<uint8_t>(lbl_regions_done - (jz_regions_done_pos + 2));

        // Apply deferred code relocations if ASLR moved ImageBase
        emit({0x48, 0x89, 0xF2});       // mov rdx, rsi (RuntimeImageBase)
        emit({0x48, 0x2B, 0x53, 0x18}); // sub rdx, qword ptr [rbx + 0x18] (preferred_image_base)
        const size_t jz_no_delta_pos = stage2.size();
        emit({0x74, 0x00});             // jz lbl_stage2_ret

        emit({0x8B, 0x4B, 0x24});       // mov ecx, dword ptr [rbx + 0x24] (code_reloc_count)
        emit({0x85, 0xC9});             // test ecx, ecx
        const size_t jz_no_relocs_pos = stage2.size();
        emit({0x74, 0x00});             // jz lbl_stage2_ret

        emit({0x4C, 0x8D, 0x83, 0x70, 0x02, 0x00, 0x00}); // lea r8, [rbx + 0x270] (&code_reloc_rvas[0])
        const size_t lbl_reloc_loop = stage2.size();
        emit({0x41, 0x8B, 0x00});       // mov eax, dword ptr [r8]
        emit({0x48, 0x01, 0x14, 0x06}); // add qword ptr [rsi + rax], rdx
        emit({0x49, 0x83, 0xC0, 0x04}); // add r8, 4
        emit({0xFF, 0xC9});             // dec ecx
        int8_t rel_reloc_loop = static_cast<int8_t>(static_cast<intptr_t>(lbl_reloc_loop) - static_cast<intptr_t>(stage2.size() + 2));
        emit({0x75, static_cast<uint8_t>(rel_reloc_loop)});

        const size_t lbl_stage2_imports = stage2.size();
        stage2[jz_no_delta_pos + 1]  = static_cast<uint8_t>(lbl_stage2_imports - (jz_no_delta_pos + 2));
        stage2[jz_no_relocs_pos + 1] = static_cast<uint8_t>(lbl_stage2_imports - (jz_no_relocs_pos + 2));

        // Resolve original Import Table (.idata) dynamically using synthetic LoadLibraryA & GetProcAddress
        emit({0x41, 0x54});             // push r12
        emit({0x41, 0x55});             // push r13
        emit({0x41, 0x56});             // push r14
        emit({0x41, 0x57});             // push r15
        emit({0x55});                   // push rbp
        emit({0x48, 0x89, 0xE5});       // mov rbp, rsp
        emit({0x48, 0x83, 0xE4, 0xF0}); // and rsp, -16
        emit({0x48, 0x83, 0xEC, 0x20}); // sub rsp, 0x20

        // mov eax, dword ptr [rbx + 0x8F0] (masked orig_import_rva)
        emit({0x8B, 0x83, 0xF0, 0x08, 0x00, 0x00});
        // xor eax, dword ptr [rbx + 0x10] (unmask with low32(master_seed))
        emit({0x33, 0x43, 0x10});
        // test eax, eax
        emit({0x85, 0xC0});
        const size_t jz_imp_done_pos = stage2.size();
        emit({0x0F, 0x84, 0, 0, 0, 0}); // jz lbl_imp_done

        // lea r12, [rsi + rax] (IMAGE_IMPORT_DESCRIPTOR* desc)
        emit({0x4C, 0x8D, 0x24, 0x06});

        const size_t lbl_desc_loop = stage2.size();
        // mov eax, dword ptr [r12 + 0x0C] (desc->Name RVA)
        emit({0x41, 0x8B, 0x44, 0x24, 0x0C});
        // test eax, eax
        emit({0x85, 0xC0});
        const size_t jz_desc_done_pos = stage2.size();
        emit({0x0F, 0x84, 0, 0, 0, 0}); // jz lbl_imp_done

        // lea rcx, [rsi + rax] (dll_name)
        emit({0x48, 0x8D, 0x0C, 0x06});
        // call qword ptr [rbx + kSynthIatOffset] (LoadLibraryA)
        emit({0xFF, 0x93, 0x48, 0x09, 0x00, 0x00});
        // test rax, rax
        emit({0x48, 0x85, 0xC0});
        const size_t jz_load_fail_pos = stage2.size();
        emit({0x0F, 0x84, 0, 0, 0, 0}); // jz lbl_imp_done
        // mov r13, rax (hMod)
        emit({0x49, 0x89, 0xC5});

        // mov eax, dword ptr [r12 + 0x00] (OriginalFirstThunk)
        emit({0x41, 0x8B, 0x04, 0x24});
        // test eax, eax
        emit({0x85, 0xC0});
        emit({0x75, 0x05}); // jnz +5
        // mov eax, dword ptr [r12 + 0x10] (FirstThunk fallback)
        emit({0x41, 0x8B, 0x44, 0x24, 0x10});
        // lea r14, [rsi + rax] (ilt)
        emit({0x4C, 0x8D, 0x34, 0x06});

        // mov eax, dword ptr [r12 + 0x10] (FirstThunk)
        emit({0x41, 0x8B, 0x44, 0x24, 0x10});
        // lea r15, [rsi + rax] (iat)
        emit({0x4C, 0x8D, 0x3C, 0x06});

        const size_t lbl_thunk_loop = stage2.size();
        // mov rax, qword ptr [r14] (*ilt)
        emit({0x49, 0x8B, 0x06});
        // test rax, rax
        emit({0x48, 0x85, 0xC0});
        const size_t jz_next_desc_pos = stage2.size();
        emit({0x74, 0x00}); // jz lbl_next_desc

        // xor rdi, rdi (will hold &IMAGE_IMPORT_BY_NAME if imported by name)
        emit({0x48, 0x31, 0xFF});
        // bt rax, 63 (check IMAGE_ORDINAL_FLAG64)
        emit({0x48, 0x0F, 0xBA, 0xE0, 0x3F});
        emit({0x72, 0x0A}); // jc by_ordinal (+10)
        // lea rdi, [rsi + rax] (IMAGE_IMPORT_BY_NAME*)
        emit({0x48, 0x8D, 0x3C, 0x06});
        // lea rdx, [rdi + 2] (&IMAGE_IMPORT_BY_NAME->Name)
        emit({0x48, 0x8D, 0x57, 0x02});
        emit({0xEB, 0x03}); // jmp do_getproc (+3)
        // by_ordinal: movzx edx, ax
        emit({0x0F, 0xB7, 0xD0});

        // do_getproc: mov rcx, r13 (hMod)
        emit({0x4C, 0x89, 0xE9});
        // call qword ptr [rbx + kSynthIatOffset + 8] (GetProcAddress)
        emit({0xFF, 0x93, 0x50, 0x09, 0x00, 0x00});
        // Wipe ILT entry first: mov qword ptr [r14], 0
        emit({0x49, 0xC7, 0x06, 0x00, 0x00, 0x00, 0x00});
        // Write resolved proc to IAT: mov qword ptr [r15], rax (*iat = proc)
        emit({0x49, 0x89, 0x07});

        // Wipe IMAGE_IMPORT_BY_NAME (2-byte Hint + ASCII function name) in RAM
        emit({0x48, 0x85, 0xFF});             // test rdi, rdi
        emit({0x74, 0x16});                   // jz skip_fn_wipe (+22)
        emit({0x66, 0xC7, 0x07, 0x00, 0x00}); // mov word ptr [rdi], 0 (Hint)
        emit({0x48, 0x83, 0xC7, 0x02});       // add rdi, 2
        // lbl_wipe_fn_char:
        emit({0x80, 0x3F, 0x00});             // cmp byte ptr [rdi], 0
        emit({0x74, 0x08});                   // jz skip_fn_wipe (+8)
        emit({0xC6, 0x07, 0x00});             // mov byte ptr [rdi], 0
        emit({0x48, 0xFF, 0xC7});             // inc rdi
        emit({0xEB, 0xF3});                   // jmp lbl_wipe_fn_char (-13)
        // skip_fn_wipe:

        // add r14, 8
        emit({0x49, 0x83, 0xC6, 0x08});
        // add r15, 8
        emit({0x49, 0x83, 0xC7, 0x08});
        int8_t rel_thunk_loop = static_cast<int8_t>(static_cast<intptr_t>(lbl_thunk_loop) - static_cast<intptr_t>(stage2.size() + 2));
        emit({0xEB, static_cast<uint8_t>(rel_thunk_loop)});

        const size_t lbl_next_desc = stage2.size();
        stage2[jz_next_desc_pos + 1] = static_cast<uint8_t>(lbl_next_desc - (jz_next_desc_pos + 2));

        // Wipe entire DLL name string (any length) in RAM so Scylla/ImpRec cannot scan it
        emit({0x41, 0x8B, 0x44, 0x24, 0x0C}); // mov eax, dword ptr [r12 + 0x0C] (desc->Name RVA)
        emit({0x48, 0x8D, 0x3C, 0x06});       // lea rdi, [rsi + rax] (dll_name string)
        // lbl_wipe_dll_char:
        emit({0x80, 0x3F, 0x00});             // cmp byte ptr [rdi], 0
        emit({0x74, 0x08});                   // jz skip_dll_wipe (+8)
        emit({0xC6, 0x07, 0x00});             // mov byte ptr [rdi], 0
        emit({0x48, 0xFF, 0xC7});             // inc rdi
        emit({0xEB, 0xF3});                   // jmp lbl_wipe_dll_char (-13)
        // skip_dll_wipe:

        // Wipe entire IMAGE_IMPORT_DESCRIPTOR (20 bytes) in RAM after resolving DLL
        emit({0x31, 0xC0});                   // xor eax, eax
        emit({0x41, 0x89, 0x04, 0x24});       // mov dword ptr [r12 + 0x00], eax
        emit({0x41, 0x89, 0x44, 0x24, 0x04}); // mov dword ptr [r12 + 0x04], eax
        emit({0x41, 0x89, 0x44, 0x24, 0x08}); // mov dword ptr [r12 + 0x08], eax
        emit({0x41, 0x89, 0x44, 0x24, 0x0C}); // mov dword ptr [r12 + 0x0C], eax
        emit({0x41, 0x89, 0x44, 0x24, 0x10}); // mov dword ptr [r12 + 0x10], eax
        // add r12, 20
        emit({0x49, 0x83, 0xC4, 0x14});
        int32_t rel_desc_loop = static_cast<int32_t>(lbl_desc_loop) - static_cast<int32_t>(stage2.size() + 5);
        emit({0xE9, 0, 0, 0, 0});
        write_i32(stage2, stage2.size() - 4, rel_desc_loop);

        const size_t lbl_imp_done = stage2.size();
        write_i32(stage2, jz_imp_done_pos + 2, static_cast<int32_t>(lbl_imp_done - (jz_imp_done_pos + 6)));
        write_i32(stage2, jz_desc_done_pos + 2, static_cast<int32_t>(lbl_imp_done - (jz_desc_done_pos + 6)));
        write_i32(stage2, jz_load_fail_pos + 2, static_cast<int32_t>(lbl_imp_done - (jz_load_fail_pos + 6)));

        emit({0x48, 0x89, 0xEC}); // mov rsp, rbp
        emit({0x5D});             // pop rbp
        emit({0x41, 0x5F});       // pop r15
        emit({0x41, 0x5E});       // pop r14
        emit({0x41, 0x5D});       // pop r13
        emit({0x41, 0x5C});       // pop r12
        emit({0xC3});             // ret to Stage 1
    }

    const uint32_t stage2_size = static_cast<uint32_t>(stage2.size());
    const uint8_t  stage2_key  = static_cast<uint8_t>(((vhdr.master_seed >> 19) & 0xFFu) | 0x05u);

    // Encrypt Stage 2 on disk using rolling byte cipher
    {
        uint8_t k = stage2_key;
        for (size_t i = 0; i < stage2.size(); ++i) {
            stage2[i] ^= k;
            k = static_cast<uint8_t>(((k << 3) | (k >> 5)) + 0x3Du);
        }
    }

    // -------------------------------------------------------------------------
    // 4. Stage 1 Self-Decrypting & Self-Wiping Bootstrap at kStage1Offset (0x280)
    // -------------------------------------------------------------------------
    {
        std::vector<uint8_t> s1;
        auto emit = [&](std::initializer_list<uint8_t> b) { s1.insert(s1.end(), b.begin(), b.end()); };

        // Save volatile + callee-saved registers
        emit({0x51});             // push rcx
        emit({0x52});             // push rdx
        emit({0x41, 0x50});       // push r8
        emit({0x41, 0x51});       // push r9
        emit({0x53});             // push rbx
        emit({0x56});             // push rsi
        emit({0x57});             // push rdi

        // Anti-disassembly opaque predicate (xor eax, eax; jz +1; db 0xE8)
        emit({0x31, 0xC0, 0x74, 0x01, 0xE8});

        // lea rbx, [rip + disp_to_header] (offset 0x000)
        int32_t disp_hdr = -static_cast<int32_t>(kStage1Offset + s1.size() + 7);
        emit({0x48, 0x8D, 0x1D, 0, 0, 0, 0});
        write_i32(s1, s1.size() - 4, disp_hdr);

        // movzx edx, word ptr [rbx + 0x06] (region_count)
        emit({0x0F, 0xB7, 0x53, 0x06});
        // test edx, edx
        emit({0x85, 0xD2});
        const size_t jz_s1_done_pos = s1.size();
        emit({0x74, 0x00}); // jz lbl_s1_done

        // Decrypt Stage 2 at [rbx + kStage2Offset]
        emit({0x48, 0x8D, 0xBB, 0, 0, 0, 0}); // lea rdi, [rbx + kStage2Offset]
        write_i32(s1, s1.size() - 4, static_cast<int32_t>(kStage2Offset));

        emit({0xB9, 0, 0, 0, 0}); // mov ecx, stage2_size
        write_i32(s1, s1.size() - 4, static_cast<int32_t>(stage2_size));

        if (enable_anti_debug) {
            // Mix PEB->NtGlobalFlag & 0x70 into Stage 2 key
            emit({0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00}); // mov rax, gs:[0x60]
            emit({0x8B, 0x80, 0xBC, 0x00, 0x00, 0x00});                   // mov eax, [rax + 0xBC]
            emit({0x83, 0xE0, 0x70});                                     // and eax, 0x70
            emit({0x34, stage2_key});                                     // xor al, stage2_key
        } else {
            emit({0xB0, stage2_key});                                     // mov al, stage2_key
        }

        const size_t lbl_s2_dec = s1.size();
        emit({0x30, 0x07});       // xor byte ptr [rdi], al
        emit({0xC0, 0xC0, 0x03}); // rol al, 3
        emit({0x04, 0x3D});       // add al, 0x3D
        emit({0x48, 0xFF, 0xC7}); // inc rdi
        emit({0xFF, 0xC9});       // dec ecx
        int8_t rel_s2_dec = static_cast<int8_t>(static_cast<intptr_t>(lbl_s2_dec) - static_cast<intptr_t>(s1.size() + 2));
        emit({0x75, static_cast<uint8_t>(rel_s2_dec)});

        // Call decrypted Stage 2 at kStage2Offset
        int32_t rel_call_s2 = static_cast<int32_t>(kStage2Offset) -
                              static_cast<int32_t>(kStage1Offset + s1.size() + 5);
        emit({0xE8, 0, 0, 0, 0});
        write_i32(s1, s1.size() - 4, rel_call_s2);

        // Immediately wipe Stage 2 machine code from RAM after execution!
        emit({0x48, 0x8D, 0xBB, 0, 0, 0, 0}); // lea rdi, [rbx + kStage2Offset]
        write_i32(s1, s1.size() - 4, static_cast<int32_t>(kStage2Offset));
        emit({0xB9, 0, 0, 0, 0});             // mov ecx, stage2_size
        write_i32(s1, s1.size() - 4, static_cast<int32_t>(stage2_size));
        emit({0x31, 0xC0});                   // xor eax, eax
        emit({0xF3, 0xAA});                   // rep stosb

        const size_t lbl_s1_done = s1.size();
        s1[jz_s1_done_pos + 1] = static_cast<uint8_t>(lbl_s1_done - (jz_s1_done_pos + 2));

        // Restore registers & return
        emit({0x5F});             // pop rdi
        emit({0x5E});             // pop rsi
        emit({0x5B});             // pop rbx
        emit({0x41, 0x59});       // pop r9
        emit({0x41, 0x58});       // pop r8
        emit({0x5A});             // pop rdx
        emit({0x59});             // pop rcx
        emit({0xC3});             // ret

        std::memcpy(sec.data() + kStage1Offset, s1.data(), s1.size());
    }

    sec.insert(sec.end(), stage2.begin(), stage2.end());
    return sec;
}

bool is_debug_or_symbol_section(const IMAGE_SECTION_HEADER& sec) noexcept {
    char name[9]{};
    std::memcpy(name, sec.Name, 8);
    // MinGW DWARF sections use "/4", "/14", "/29", etc. or ".debug*"
    if (name[0] == '/' || std::strncmp(name, ".debug", 6) == 0) {
        return true;
    }
    return false;
}

} // namespace

bool PeImage::load_from_file(const std::string& path, std::string* err) {
    std::ifstream ifs(path, std::ios::binary | std::ios::ate);
    if (!ifs) {
        if (err) *err = "Cannot open file: " + path;
        return false;
    }
    auto end_pos = ifs.tellg();
    if (end_pos <= 0) {
        if (err) *err = "File is empty: " + path;
        return false;
    }
    std::vector<uint8_t> buf(static_cast<size_t>(end_pos));
    ifs.seekg(0, std::ios::beg);
    if (!ifs.read(reinterpret_cast<char*>(buf.data()), end_pos)) {
        if (err) *err = "Failed to read file bytes: " + path;
        return false;
    }
    return load_from_memory(std::move(buf), err);
}

bool PeImage::load_from_memory(std::vector<uint8_t> data, std::string* err) {
    valid_pe64_ = false;
    nt_headers_offset_ = 0;

    if (data.size() < sizeof(IMAGE_DOS_HEADER)) {
        if (err) *err = "Buffer smaller than IMAGE_DOS_HEADER";
        return false;
    }

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(data.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        if (err) *err = "Invalid DOS MZ signature";
        return false;
    }

    uint32_t lfanew = static_cast<uint32_t>(dos->e_lfanew);
    if (lfanew + sizeof(IMAGE_NT_HEADERS64) > data.size()) {
        if (err) *err = "Invalid e_lfanew offset";
        return false;
    }

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(data.data() + lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        if (err) *err = "Invalid PE NT signature";
        return false;
    }

    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        if (err) *err = "Only 64-bit PE (PE32+ / AMD64) binaries are supported";
        return false;
    }

    data_ = std::move(data);
    nt_headers_offset_ = lfanew;
    valid_pe64_ = true;
    return true;
}

bool PeImage::save_to_file(const std::string& path, std::string* err) const {
    if (!valid_pe64_) {
        if (err) *err = "No valid PE64 image loaded";
        return false;
    }
    std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
    if (!ofs) {
        if (err) *err = "Cannot open output file for writing: " + path;
        return false;
    }
    ofs.write(reinterpret_cast<const char*>(data_.data()), static_cast<std::streamsize>(data_.size()));
    if (!ofs.good()) {
        if (err) *err = "Failed while writing output file: " + path;
        return false;
    }
    return true;
}

uint64_t PeImage::image_base() const noexcept {
    if (!valid_pe64_) return 0;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(data_.data() + nt_headers_offset_);
    return nt->OptionalHeader.ImageBase;
}

uint32_t PeImage::entry_point_rva() const noexcept {
    if (!valid_pe64_) return 0;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(data_.data() + nt_headers_offset_);
    return nt->OptionalHeader.AddressOfEntryPoint;
}

uint32_t PeImage::size_of_image() const noexcept {
    if (!valid_pe64_) return 0;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(data_.data() + nt_headers_offset_);
    return nt->OptionalHeader.SizeOfImage;
}

std::vector<SectionInfo> PeImage::list_sections() const {
    std::vector<SectionInfo> result;
    if (!valid_pe64_) return result;

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(data_.data() + nt_headers_offset_);
    const IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    result.reserve(nt->FileHeader.NumberOfSections);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        char name_buf[9]{};
        std::memcpy(name_buf, sec->Name, 8);
        SectionInfo info;
        info.name = name_buf;
        info.virtual_address = sec->VirtualAddress;
        info.virtual_size = sec->Misc.VirtualSize;
        info.raw_offset = sec->PointerToRawData;
        info.raw_size = sec->SizeOfRawData;
        info.characteristics = sec->Characteristics;
        result.push_back(std::move(info));
    }
    return result;
}

bool PeImage::find_section(const std::string& name, SectionInfo& out_sec) const {
    for (const auto& s : list_sections()) {
        if (s.name == name) {
            out_sec = s;
            return true;
        }
    }
    return false;
}

bool PeImage::rva_to_file_offset(uint32_t rva, uint32_t& out_offset) const noexcept {
    if (!valid_pe64_) return false;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(data_.data() + nt_headers_offset_);
    const IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        uint32_t sec_span = sec->Misc.VirtualSize ? sec->Misc.VirtualSize : sec->SizeOfRawData;
        if (rva >= sec->VirtualAddress && rva < sec->VirtualAddress + sec_span) {
            uint32_t delta = rva - sec->VirtualAddress;
            if (delta < sec->SizeOfRawData && sec->PointerToRawData + delta < data_.size()) {
                out_offset = sec->PointerToRawData + delta;
                return true;
            }
            return false;
        }
    }
    return false;
}

bool PeImage::is_already_packed(VPackHeader* out_header) const noexcept {
    SectionInfo sec{};
    if (!find_section(".vpack", sec)) {
        return false;
    }
    if (sec.raw_offset + sizeof(VPackHeader) > data_.size()) {
        return false;
    }
    const auto* hdr = reinterpret_cast<const VPackHeader*>(data_.data() + sec.raw_offset);
    uint32_t expected_magic = static_cast<uint32_t>(hdr->master_seed ^ 0xFFFFFFFFULL) ^ VPACK_MAGIC;
    if (hdr->magic != expected_magic) {
        return false;
    }
    if (out_header) {
        *out_header = *hdr;
        out_header->original_entry_rva ^= static_cast<uint32_t>(hdr->master_seed & 0xFFFFFFFFULL);
        out_header->orig_tls_callback_rva ^= static_cast<uint32_t>((hdr->master_seed >> 32) & 0xFFFFFFFFULL);
    }
    return true;
}

PackResult PeImage::pack(const PackOptions& opts) {
    PackResult res{};
    if (!valid_pe64_) {
        res.message = "Invalid PE64 image";
        return res;
    }

    if (is_already_packed()) {
        res.message = "Binary is already packed with .vpack";
        return res;
    }

    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(data_.data() + nt_headers_offset_);
    IMAGE_SECTION_HEADER* first_sec = IMAGE_FIRST_SECTION(nt);
    uint16_t num_sec = nt->FileHeader.NumberOfSections;

    // 1. Strip COFF Symbol Table, String Table, Debug Directory, and DWARF sections (/4, /14, ...)
    uint32_t stripped_count = 0;
    if (opts.strip_symbols_and_debug) {
        nt->FileHeader.PointerToSymbolTable = 0;
        nt->FileHeader.NumberOfSymbols      = 0;
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0;
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size           = 0;

        uint16_t kept_sec = 0;
        for (uint16_t i = 0; i < num_sec; ++i) {
            if (is_debug_or_symbol_section(first_sec[i])) {
                ++stripped_count;
                continue;
            }
            if (kept_sec != i) {
                first_sec[kept_sec] = first_sec[i];
            }
            ++kept_sec;
        }
        if (stripped_count > 0) {
            std::memset(&first_sec[kept_sec], 0, sizeof(IMAGE_SECTION_HEADER) * (num_sec - kept_sec));
            num_sec = kept_sec;
            nt->FileHeader.NumberOfSections = num_sec;
        }

        // Truncate trailing COFF symbols / debug payload past the last kept section
        uint32_t max_kept_raw = nt->OptionalHeader.SizeOfHeaders;
        for (uint16_t i = 0; i < num_sec; ++i) {
            uint32_t end_raw = first_sec[i].PointerToRawData + first_sec[i].SizeOfRawData;
            if (end_raw > max_kept_raw) {
                max_kept_raw = end_raw;
            }
        }
        if (max_kept_raw < data_.size()) {
            data_.resize(max_kept_raw);
            nt        = reinterpret_cast<IMAGE_NT_HEADERS64*>(data_.data() + nt_headers_offset_);
            first_sec = IMAGE_FIRST_SECTION(nt);
        }
    }

    // Verify space in header for .vpack IMAGE_SECTION_HEADER
    const uint32_t new_sec_hdr_end = static_cast<uint32_t>(
        reinterpret_cast<const uint8_t*>(&first_sec[num_sec + 1]) - data_.data()
    );
    if (new_sec_hdr_end > nt->OptionalHeader.SizeOfHeaders) {
        res.message = "Not enough space in PE header to append .vpack section header";
        return res;
    }

    uint64_t seed = opts.custom_seed;
    if (seed == 0) {
        auto now = static_cast<uint64_t>(
            std::chrono::high_resolution_clock::now().time_since_epoch().count()
        );
        seed = crypto::fnv1a_64(data_.data(), data_.size()) ^ now ^ 0x5341424C455F504BULL;
    }

    const uint32_t file_align = nt->OptionalHeader.FileAlignment;
    const uint32_t sec_align  = nt->OptionalHeader.SectionAlignment;

    uint32_t max_virt_end = 0;
    uint32_t max_raw_end  = static_cast<uint32_t>(data_.size());
    for (WORD i = 0; i < num_sec; ++i) {
        uint32_t v_span = first_sec[i].Misc.VirtualSize ? first_sec[i].Misc.VirtualSize : first_sec[i].SizeOfRawData;
        uint32_t v_end  = first_sec[i].VirtualAddress + v_span;
        if (v_end > max_virt_end) max_virt_end = v_end;

        uint32_t r_end = first_sec[i].PointerToRawData + first_sec[i].SizeOfRawData;
        if (r_end > max_raw_end) max_raw_end = r_end;
    }

    const uint32_t new_sec_va = align_up(max_virt_end, sec_align);

    const uint32_t seed_lo = static_cast<uint32_t>(seed & 0xFFFFFFFFULL);
    const uint32_t seed_hi = static_cast<uint32_t>((seed >> 32) & 0xFFFFFFFFULL);
    const uint32_t orig_ep_plain = nt->OptionalHeader.AddressOfEntryPoint;

    VPackHeader vhdr{};
    vhdr.magic                = (seed_lo ^ 0xFFFFFFFFu) ^ VPACK_MAGIC;
    vhdr.version              = VPACK_VERSION;
    vhdr.region_count         = 0;
    vhdr.flags                = opts.protection_flags;
    vhdr.original_entry_rva   = orig_ep_plain ^ seed_lo;
    vhdr.master_seed          = seed;
    vhdr.preferred_image_base = nt->OptionalHeader.ImageBase;
    vhdr.orig_tls_callback_rva = seed_hi; // 0 ^ seed_hi
    vhdr.code_reloc_count     = 0;
    vhdr.orig_pdata_rva       = 0;
    vhdr.orig_pdata_size      = 0;
    vhdr.orig_import_rva      = seed_lo; // 0 ^ seed_lo
    vhdr.vcode_rva            = seed_lo; // 0 ^ seed_lo
    vhdr.vcode_size           = seed_hi; // 0 ^ seed_hi
    vhdr.vcode_jit_tag        = 0;

    for (WORD i = 0; i < num_sec; ++i) {
        char sname[9]{};
        std::memcpy(sname, first_sec[i].Name, 8);
        if (std::strcmp(sname, ".vcode") == 0) {
            uint32_t vc_size = first_sec[i].Misc.VirtualSize;
            if (vc_size == 0 || vc_size > first_sec[i].SizeOfRawData) {
                vc_size = first_sec[i].SizeOfRawData;
            }
            vhdr.vcode_rva     = first_sec[i].VirtualAddress ^ seed_lo;
            vhdr.vcode_size    = vc_size ^ seed_hi;
            vhdr.vcode_jit_tag = static_cast<uint32_t>(seed ^ 0x4A495456ULL);
            break;
        }
    }

    // 2. Hook first TLS Callback if present so .text is decrypted BEFORE TLS initializers execute
    const auto& tls_dir_entry = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (tls_dir_entry.VirtualAddress != 0 && tls_dir_entry.Size >= sizeof(IMAGE_TLS_DIRECTORY64)) {
        uint32_t tls_off = 0;
        if (rva_to_file_offset(tls_dir_entry.VirtualAddress, tls_off) &&
            tls_off + sizeof(IMAGE_TLS_DIRECTORY64) <= data_.size()) {
            const auto* tls_dir = reinterpret_cast<const IMAGE_TLS_DIRECTORY64*>(data_.data() + tls_off);
            if (tls_dir->AddressOfCallBacks > nt->OptionalHeader.ImageBase) {
                uint32_t cb_array_rva = static_cast<uint32_t>(tls_dir->AddressOfCallBacks - nt->OptionalHeader.ImageBase);
                uint32_t cb_off = 0;
                if (rva_to_file_offset(cb_array_rva, cb_off) && cb_off + sizeof(uint64_t) <= data_.size()) {
                    auto* cb_slot = reinterpret_cast<uint64_t*>(data_.data() + cb_off);
                    if (*cb_slot > nt->OptionalHeader.ImageBase) {
                        uint32_t tls_cb_plain = static_cast<uint32_t>(*cb_slot - nt->OptionalHeader.ImageBase);
                        vhdr.orig_tls_callback_rva = tls_cb_plain ^ seed_hi;
                        *cb_slot = nt->OptionalHeader.ImageBase + new_sec_va + kTlsStubOffset;
                    }
                }
            }
        }
    }

    // Helper to encrypt a sub-range [range_rva, range_rva + range_size) inside section i
    auto encrypt_section_range = [&](WORD sec_idx, uint32_t range_rva, uint32_t range_size, uint64_t key_salt) {
        if (vhdr.region_count >= VPACK_MAX_REGIONS || range_size == 0) return;
        uint32_t sec_va  = first_sec[sec_idx].VirtualAddress;
        uint32_t sec_raw = first_sec[sec_idx].PointerToRawData;
        if (range_rva < sec_va) return;
        uint32_t offset_in_sec = range_rva - sec_va;
        if (offset_in_sec + range_size > first_sec[sec_idx].SizeOfRawData) return;
        if (sec_raw + offset_in_sec + range_size > data_.size()) return;

        // Defer any base relocations inside this encrypted range
        const auto& reloc_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (reloc_dir.VirtualAddress != 0 && reloc_dir.Size > 0) {
            uint32_t rel_off = 0;
            if (rva_to_file_offset(reloc_dir.VirtualAddress, rel_off)) {
                uint32_t parsed = 0;
                while (parsed + sizeof(IMAGE_BASE_RELOCATION) <= reloc_dir.Size &&
                       rel_off + parsed + sizeof(IMAGE_BASE_RELOCATION) <= data_.size()) {
                    auto* blk = reinterpret_cast<IMAGE_BASE_RELOCATION*>(data_.data() + rel_off + parsed);
                    if (blk->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) break;
                    uint32_t count = (blk->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
                    auto* entries = reinterpret_cast<uint16_t*>(blk + 1);
                    for (uint32_t k = 0; k < count; ++k) {
                        uint16_t type = entries[k] >> 12;
                        uint16_t off  = entries[k] & 0x0FFF;
                        uint32_t rva  = blk->VirtualAddress + off;
                        if (type == IMAGE_REL_BASED_DIR64 &&
                            rva >= range_rva &&
                            rva < range_rva + range_size) {
                            if (vhdr.code_reloc_count < VPACK_MAX_CODE_RELOCS) {
                                vhdr.code_reloc_rvas[vhdr.code_reloc_count++] = rva;
                                entries[k] = 0; // Turn into IMAGE_REL_BASED_ABSOLUTE no-op for OS loader
                            }
                        }
                    }
                    parsed += blk->SizeOfBlock;
                }
            }
        }

        uint8_t* sec_bytes  = data_.data() + sec_raw + offset_in_sec;
        uint64_t region_key = seed ^ key_salt;
        uint64_t plain_hash = crypto::fnv1a_64(sec_bytes, range_size);

        stub_stream_xor(sec_bytes, range_size, region_key);

        first_sec[sec_idx].Characteristics |= (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE);

        VPackRegion& reg = vhdr.regions[vhdr.region_count++];
        reg.rva        = range_rva ^ seed_lo;
        reg.size       = range_size ^ seed_hi;
        reg.key        = region_key;
        reg.plain_hash = plain_hash;
    };

    // Helper to encrypt a named section and add it to VPackHeader
    auto encrypt_section_by_name = [&](const char* target_name, uint64_t key_salt) {
        if (vhdr.region_count >= VPACK_MAX_REGIONS) return;
        for (WORD i = 0; i < num_sec; ++i) {
            char sname[9]{};
            std::memcpy(sname, first_sec[i].Name, 8);
            if (std::strcmp(sname, target_name) == 0) {
                uint32_t enc_size = first_sec[i].Misc.VirtualSize;
                if (enc_size == 0 || enc_size > first_sec[i].SizeOfRawData) {
                    enc_size = first_sec[i].SizeOfRawData;
                }
                encrypt_section_range(i, first_sec[i].VirtualAddress, enc_size, key_salt);
                break;
            }
        }
    };

    // 3. Encrypt .text, .vcode, .pdata, .xdata, and .rdata string pool
    if (opts.encrypt_text_section) {
        encrypt_section_by_name(".text", 0x544558545F4B4559ULL);
    }
    if (opts.encrypt_vcode_section) {
        encrypt_section_by_name(".vcode", 0xA5A5F0F033CCAA55ULL);
    }
    if (opts.encrypt_pdata_section) {
        auto& exc_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (exc_dir.VirtualAddress != 0 && exc_dir.Size != 0) {
            vhdr.orig_pdata_rva  = exc_dir.VirtualAddress;
            vhdr.orig_pdata_size = exc_dir.Size;
            // Hide Exception Directory from static analysis tools (IDA Pro uses .pdata to find all functions)
            exc_dir.VirtualAddress = 0;
            exc_dir.Size           = 0;
        }
        encrypt_section_by_name(".pdata", 0x50444154415F4B59ULL);
        encrypt_section_by_name(".xdata", 0x58444154415F4B59ULL);
    }

    // Encrypt original .idata section and redirect Import Directory to the 2-function synthetic table in .vpack
    {
        auto& imp_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (imp_dir.VirtualAddress != 0 && imp_dir.Size != 0) {
            vhdr.orig_import_rva   = imp_dir.VirtualAddress ^ seed_lo;
            imp_dir.VirtualAddress = new_sec_va + kSynthImportOffset;
            imp_dir.Size           = sizeof(IMAGE_IMPORT_DESCRIPTOR) * 2;

            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = 0;
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size           = 0;
            encrypt_section_by_name(".idata", 0x49444154415F4B59ULL);
        }
    }

    // Encrypt all contiguous relocation/TLS-free intervals (>= 64 bytes) in .rdata
    for (WORD i = 0; i < num_sec; ++i) {
        char sname[9]{};
        std::memcpy(sname, first_sec[i].Name, 8);
        if (std::strcmp(sname, ".rdata") == 0) {
            uint32_t rdata_va   = first_sec[i].VirtualAddress;
            uint32_t rdata_size = first_sec[i].Misc.VirtualSize;
            if (rdata_size == 0 || rdata_size > first_sec[i].SizeOfRawData) {
                rdata_size = first_sec[i].SizeOfRawData;
            }
            const uint32_t span = rdata_size;
            std::vector<uint8_t> has_reloc(span, 0);

            auto mark_excluded = [&](uint32_t ex_rva, uint32_t ex_len) {
                if (ex_rva + ex_len <= rdata_va || ex_rva >= rdata_va + span) return;
                uint32_t start_off = (ex_rva > rdata_va) ? (ex_rva - rdata_va) : 0;
                uint32_t end_off   = (ex_rva + ex_len < rdata_va + span) ? (ex_rva + ex_len - rdata_va) : span;
                for (uint32_t b = start_off; b < end_off; ++b) {
                    has_reloc[b] = 1;
                }
            };

            const auto& tls_d = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
            if (tls_d.VirtualAddress != 0 && tls_d.Size != 0) {
                mark_excluded(tls_d.VirtualAddress, tls_d.Size + 16);
                uint32_t tls_off = 0;
                if (rva_to_file_offset(tls_d.VirtualAddress, tls_off) &&
                    tls_off + sizeof(IMAGE_TLS_DIRECTORY64) <= data_.size()) {
                    const auto* tls_dir = reinterpret_cast<const IMAGE_TLS_DIRECTORY64*>(data_.data() + tls_off);
                    if (tls_dir->AddressOfCallBacks > nt->OptionalHeader.ImageBase) {
                        uint32_t cb_rva = static_cast<uint32_t>(tls_dir->AddressOfCallBacks - nt->OptionalHeader.ImageBase);
                        mark_excluded(cb_rva, 64);
                    }
                }
            }

            const auto& reloc_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
            if (span > 0 && reloc_dir.VirtualAddress != 0 && reloc_dir.Size > 0) {
                uint32_t rel_off = 0;
                if (rva_to_file_offset(reloc_dir.VirtualAddress, rel_off)) {
                    uint32_t parsed = 0;
                    while (parsed + sizeof(IMAGE_BASE_RELOCATION) <= reloc_dir.Size &&
                           rel_off + parsed + sizeof(IMAGE_BASE_RELOCATION) <= data_.size()) {
                        const auto* blk = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(data_.data() + rel_off + parsed);
                        if (blk->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) break;
                        uint32_t count = (blk->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
                        const auto* entries = reinterpret_cast<const uint16_t*>(blk + 1);
                        for (uint32_t k = 0; k < count; ++k) {
                            uint16_t type = entries[k] >> 12;
                            uint16_t off  = entries[k] & 0x0FFF;
                            uint32_t rva  = blk->VirtualAddress + off;
                            if (type != IMAGE_REL_BASED_ABSOLUTE) {
                                mark_excluded(rva, 8);
                            }
                        }
                        parsed += blk->SizeOfBlock;
                    }
                }
            }

            uint32_t cur = 0;
            uint64_t salt_counter = 0x52444154415F4B31ULL;
            while (cur < span && vhdr.region_count < VPACK_MAX_REGIONS) {
                while (cur < span && has_reloc[cur]) ++cur;
                uint32_t start = cur;
                while (cur < span && !has_reloc[cur]) ++cur;
                uint32_t len = cur - start;
                if (len >= 16) {
                    encrypt_section_range(i, rdata_va + start, len, salt_counter++);
                }
            }
            break;
        }
    }

    // Masquerade section names so static analyzers cannot identify .vcode/.pdata/.xdata/.eh_fram
    for (WORD i = 0; i < num_sec; ++i) {
        char sname[9]{};
        std::memcpy(sname, first_sec[i].Name, 8);
        if (std::strcmp(sname, ".vcode") == 0 ||
            std::strcmp(sname, ".pdata") == 0 ||
            std::strcmp(sname, ".xdata") == 0 ||
            std::strcmp(sname, ".idata") == 0 ||
            std::strcmp(sname, ".eh_fram") == 0) {
            char obf_name[8]{'.', 's', 'b', 'l', static_cast<char>('0' + (i % 10)), 0, 0, 0};
            std::memcpy(first_sec[i].Name, obf_name, 8);
        }
    }

    // 4. Build .vpack section payload
    std::vector<uint8_t> vpack_sec_data = build_vpack_section_payload(vhdr, new_sec_va, opts.stub_anti_debug);

    const uint32_t new_sec_raw_ptr  = align_up(max_raw_end, file_align);
    const uint32_t new_sec_vsize    = static_cast<uint32_t>(vpack_sec_data.size());
    const uint32_t new_sec_raw_size = align_up(new_sec_vsize, file_align);

    if (data_.size() < new_sec_raw_ptr + new_sec_raw_size) {
        data_.resize(new_sec_raw_ptr + new_sec_raw_size, 0);
    }
    std::memcpy(data_.data() + new_sec_raw_ptr, vpack_sec_data.data(), vpack_sec_data.size());

    // Re-acquire pointers after vector resize
    nt        = reinterpret_cast<IMAGE_NT_HEADERS64*>(data_.data() + nt_headers_offset_);
    first_sec = IMAGE_FIRST_SECTION(nt);

    IMAGE_SECTION_HEADER& new_sec = first_sec[num_sec];
    std::memset(&new_sec, 0, sizeof(IMAGE_SECTION_HEADER));
    std::memcpy(new_sec.Name, ".vpack", 6);
    new_sec.Misc.VirtualSize = new_sec_vsize;
    new_sec.VirtualAddress   = new_sec_va;
    new_sec.SizeOfRawData    = new_sec_raw_size;
    new_sec.PointerToRawData = new_sec_raw_ptr;
    new_sec.Characteristics  = IMAGE_SCN_CNT_CODE | IMAGE_SCN_CNT_INITIALIZED_DATA |
                               IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

    nt->FileHeader.NumberOfSections = static_cast<WORD>(num_sec + 1);
    nt->OptionalHeader.SizeOfImage  = align_up(new_sec_va + new_sec_vsize, sec_align);

    uint32_t new_ep_rva = orig_ep_plain;
    if (opts.inject_entry_stub) {
        new_ep_rva = new_sec_va + kEpStubOffset;
        nt->OptionalHeader.AddressOfEntryPoint = new_ep_rva;
    }

    nt->OptionalHeader.CheckSum = 0;

    res.success            = true;
    res.message            = "Successfully packed PE64 (.text + .vcode + .pdata encrypted, symbols stripped)";
    res.original_entry_rva = orig_ep_plain;
    res.new_entry_rva      = new_ep_rva;
    res.encrypted_regions  = vhdr.region_count;
    res.stripped_sections  = stripped_count;
    res.output_size        = data_.size();
    return res;
}

} // namespace vpack::pe
