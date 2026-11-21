#include "vpack/pe_parser.h"
#include "vpack/virtualizer.h"
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

constexpr uint64_t rotl64(uint64_t x, int n) noexcept {
    return (x << n) | (x >> (64 - n));
}

constexpr uint64_t kGold64     = 0x9E3779B97F4A7C15ULL;
constexpr uint64_t kM1         = 0xBF58476D1CE4E5B9ULL;
constexpr uint64_t kM2         = 0x94D049BB133111EBULL;
constexpr uint64_t kBridgeSalt = 0x5AF1C0DE9E3779B9ULL;

// ============================================================================
// Plaintext-Feedback Chained Stream Cipher (pack-side mirror of Stage 2 asm)
//   per byte:  s = rotl64(s,13) * kM1 ; ks = s & 0xFF
//              enc = plain ^ ks ; s = (s & ~0xFF) | ((s + plain) & 0xFF)
// Patching or NOPing any ciphertext byte corrupts the entire remainder (L1/L7).
// ============================================================================
uint8_t chained_ks_step(uint64_t& s) noexcept {
    s = rotl64(s, 13) * kM1;
    return static_cast<uint8_t>(s & 0xFFULL);
}

void chained_feed_plain(uint64_t& s, uint8_t plain) noexcept {
    s = (s & ~0xFFULL) | (((s & 0xFFULL) + plain) & 0xFFULL);
}

void chained_encrypt(uint8_t* data, size_t size, uint64_t key) noexcept {
    uint64_t s = key;
    for (size_t i = 0; i < size; ++i) {
        const uint8_t ks    = chained_ks_step(s);
        const uint8_t plain = data[i];
        data[i] = static_cast<uint8_t>(plain ^ ks);
        chained_feed_plain(s, plain);
    }
}

// Standard reflected CRC-32 (poly 0xEDB88320) — bit-exact with the Stage 1 asm loop.
uint32_t crc32_ieee(const uint8_t* p, size_t n) noexcept {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; ++i) {
        crc ^= p[i];
        for (int b = 0; b < 8; ++b) {
            crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
        }
    }
    return ~crc;
}

// ============================================================================
// LZSS Compressor (pack-time, L6): breaks the 1:1 chunk<->section mapping.
// Stream consumed by the Stage 2 asm decoder:
//   chunk = [noise byte (bit1 set — never 0x00/0x01)] [flag byte] [8 tokens]
//   flag bit 1 = literal byte; flag bit 0 = match [len-4][dist_lo][dist_hi]
//   terminator chunk = [0x01][0x80]; the decoder stops by produced-byte count.
// ============================================================================
std::vector<uint8_t> lzss_compress(const uint8_t* data, size_t size, uint64_t seed) noexcept {
    std::vector<uint8_t> out;
    out.reserve(size / 2 + 16);

    uint64_t noise = seed ^ kGold64;
    auto next_noise = [&noise]() noexcept {
        noise = (noise << 13) ^ (noise >> 7) ^ 0x517CC1B727220A95ULL;
        return noise;
    };

    size_t pos = 0;
    while (pos < size) {
        out.push_back(static_cast<uint8_t>(next_noise() | 0x02));

        size_t token_count = 0;
        size_t flag_pos    = out.size();
        out.push_back(0x00);

        while (pos < size && token_count < 8) {
            size_t best_len  = 0;
            size_t best_dist = 0;
            const size_t max_len   = size - pos;
            const size_t win_start = (pos > 65535) ? (pos - 65535) : 0;

            if (max_len >= 4) {
                const uint32_t tag = static_cast<uint32_t>(data[pos]) |
                                     (static_cast<uint32_t>(data[pos + 1]) << 8) |
                                     (static_cast<uint32_t>(data[pos + 2]) << 16) |
                                     (static_cast<uint32_t>(data[pos + 3]) << 24);
                for (size_t cand = win_start; cand + 4 <= pos; ++cand) {
                    if (reinterpret_cast<const uint32_t&>(data[cand]) == tag) {
                        size_t len = 4;
                        while (len < max_len && len < 259 && data[cand + len] == data[pos + len]) {
                            ++len;
                        }
                        if (len > best_len) {
                            best_len  = len;
                            best_dist = pos - cand;
                            if (best_len >= 32) break;
                        }
                    }
                }
            }

            if (best_len >= 4 && best_dist <= 65535) {
                out.push_back(static_cast<uint8_t>(best_len - 4));
                out.push_back(static_cast<uint8_t>(best_dist & 0xFF));
                out.push_back(static_cast<uint8_t>((best_dist >> 8) & 0xFF));
                pos += best_len;
            } else {
                out[flag_pos] = static_cast<uint8_t>(out[flag_pos] | (1u << token_count));
                out.push_back(data[pos]);
                pos += 1;
            }
            ++token_count;
        }
    }

    out.push_back(0x01);
    out.push_back(0x80);
    return out;
}

constexpr uint64_t derive_secret_stub_share(uint64_t real_seed) noexcept {
    return crypto::poly_permute_64(real_seed ^ 0x7A91E3C5D82B4F19ULL, 0xE593A1C78D2B4F61ULL) | 0x4000000040000001ULL;
}

constexpr uint64_t derive_morph_key(uint64_t real_seed) noexcept {
    return crypto::poly_permute_64(real_seed, 0xB981C7E3D52A9F47ULL);
}

constexpr uint32_t kDecoyImportOffset = 0x900;
constexpr uint32_t kStolenOepOffset   = 0x9C0;
constexpr uint32_t kStolenOepSpan     = 0x40;
constexpr uint32_t kStolenOepBytes    = 24;

constexpr uint32_t kEpStubOffset  = 0xA00;
constexpr uint32_t kTlsStubOffset = 0xA40;
constexpr uint32_t kStage1Offset  = 0xB00;
constexpr uint32_t kStage2Offset  = 0xE80; // 0x380 (896B) reserved for Stage 1 (PEB walk + VP unlock + CRC + decrypt)

constexpr uint32_t kIdRegionM1  = 10;
constexpr uint32_t kIdRegionM2  = 11;
constexpr uint32_t kIdRelocMask = 12;
constexpr uint32_t kIdKeyMaskLo = 13;
constexpr uint32_t kIdKeyMaskHi = 14;

// Stage 2 scratch slots (wiped by the legacy wipe before returning to Stage 1)
constexpr uint32_t kScrKeyMask64 = 0x30;
constexpr uint32_t kScrM1        = 0x38;
constexpr uint32_t kScrM2        = 0x3C;
constexpr uint32_t kScrTlsRva    = 0x40;
constexpr uint32_t kScrRelocMask = 0x44;
constexpr uint32_t kScrStreamM2  = 0x48;
constexpr uint32_t kScrPubSalt   = 0x50;
constexpr uint32_t kScrMagicM    = 0x58;
constexpr uint32_t kScrLLA       = 0x60;
constexpr uint32_t kScrGPA       = 0x68;
constexpr uint32_t kScrVP        = 0x70;
constexpr uint32_t kScrIlt       = 0x78;
constexpr uint32_t kScrIat       = 0x80;
constexpr uint32_t kScrPoison    = 0x88;
constexpr uint32_t kScrBlobBase  = 0x90;

// Runtime handoff slots (strictly below 0x8F0 so vcode_rva/vcode_size/vinit_rva/vinit_size stay intact!)
constexpr uint32_t kScrPubSaltFinal = 0x8D0; // 8B: public_salt for SDK
constexpr uint32_t kScrLiveVcodeKey  = 0x8D8; // 8B: masked initial K_live for SDK
constexpr uint32_t kScrTlsCbPair    = 0x8E0; // 8B: cb0_rva | (cb1_rva << 32) for EpStub replay
constexpr uint32_t kLegacyWipeLen    = kScrPubSaltFinal - 0x30; // 0x8A0 (preserve 0x8C8+ handoff slots)

constexpr uint64_t kHashKernelBase       = crypto::fnv1a_64_ci_constexpr("kernelbase.dll");
constexpr uint64_t kHashVirtualProtect = crypto::fnv1a_64_ci_constexpr("VirtualProtect");
constexpr uint64_t kHashLoadLibraryA   = crypto::fnv1a_64_ci_constexpr("LoadLibraryA");
constexpr uint64_t kHashGetProcAddr    = crypto::fnv1a_64_ci_constexpr("GetProcAddress");
constexpr uint64_t kFnvBasis           = 0xCBF29CE484222325ULL;
constexpr uint64_t kFnvPrime           = 0x100000001B3ULL;

constexpr uint64_t kLiveKeySalt = 0x59E3779B7F4A7C15ULL;

// ============================================================================
// Byte emitter with rel8/rel32 backpatch bookkeeping
// ============================================================================
struct CodeBuf {
    std::vector<uint8_t> c;

    void operator()(std::initializer_list<uint8_t> b) { c.insert(c.end(), b.begin(), b.end()); }

    void u64(uint64_t v) {
        for (int i = 0; i < 8; ++i) c.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
    }
    void patch32(size_t pos, int32_t v) {
        for (int i = 0; i < 4; ++i) c[pos + i] = static_cast<uint8_t>((v >> (i * 8)) & 0xFF);
    }
    int32_t here() const { return static_cast<int32_t>(c.size()); }

    // Reserve a forward rel8 slot; returns the byte position to patch later.
    size_t fwd8() { return c.size() + 1; }
    void set8(size_t pos, size_t target) {
        c[pos] = static_cast<uint8_t>(static_cast<int64_t>(target) - static_cast<int64_t>(pos + 1));
    }
    // Emit a backward rel8 jump immediately (2-byte instruction: opcode + rel8).
    void back8(uint8_t opcode, size_t target) {
        const int32_t rel = static_cast<int32_t>(target) - (static_cast<int32_t>(c.size()) + 2);
        c.push_back(opcode);
        c.push_back(static_cast<uint8_t>(rel));
    }
    void u32(uint32_t v) {
        for (int i = 0; i < 4; ++i) c.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
    }
    // Reserve a forward rel32 jz (0F 84) — returns position of rel32 field.
    size_t jz32() {
        (*this)({0x0F, 0x84, 0, 0, 0, 0});
        return c.size() - 4;
    }
    // Emit a backward/forward rel32 jnz (0F 85) to an already-known target.
    void jnz32_to(size_t target) {
        (*this)({0x0F, 0x85, 0, 0, 0, 0});
        patch32(c.size() - 4, static_cast<int32_t>(target) - here());
    }
    // Emit a rel32 jmp (E9) to an already-known target.
    void jmp32_to(size_t target) {
        (*this)({0xE9, 0, 0, 0, 0});
        patch32(c.size() - 4, static_cast<int32_t>(target) - here());
    }
};

// ============================================================================
// Stage 2 emitter — hand-encoded x86-64. Register map:
//   rbx = VPackHeader*          rsi = runtime ImageBase
//   rdi = decode destination    r9  = poison -> LZSS flag byte
//   r10 = chained cipher state  r11 = constants
//   r12 = blob src / import desc r13 = match scratch / hMod
//   r14 = handshake base (pub_salt ^ ImageBase ^ poison)   r15 = real_seed
//   rax, rcx, rdx = scratch
//   [rsp+0x10] ilt  [rsp+0x18] iat  [rsp+0x20] scratch  [rsp+0x28] counters
// ============================================================================
struct Stage2Out {
    std::vector<uint8_t> code;
    size_t fix_regions_table = SIZE_MAX;
    size_t fix_relocs_table  = SIZE_MAX;
    size_t fix_blobs_table   = SIZE_MAX;
};

Stage2Out emit_stage2(
    uint64_t secret_share,
    size_t   region_count,
    size_t   reloc_count,
    uint32_t bridge_rva,
    uint64_t tls_cb_pair,
    bool     enable_anti_debug
) {
    CodeBuf e;
    Stage2Out out;
    std::vector<size_t> fix_imp_done;
    std::vector<size_t> fix_regions_done;
    std::vector<size_t> fix_reloc_done;
    std::vector<size_t> fix_skip_live;
    std::vector<size_t> fix_next_region;

    // SplitMix64 field mask -> eax (clobbers rdx, r11)
    auto mask32 = [&](bool from_hb, uint32_t id) {
        if (from_hb) e({0x4C, 0x89, 0xF0});            // mov rax, r14
        else         e({0x4C, 0x89, 0xF8});            // mov rax, r15
        e({0x49, 0xBB}); e.u64((static_cast<uint64_t>(id) + 1ULL) * kGold64);
        e({0x4C, 0x31, 0xD8});                          // xor rax, r11
        e({0x49, 0xBB}); e.u64(kM1);
        e({0x48, 0x89, 0xC2});                          // mov rdx, rax
        e({0x48, 0xC1, 0xEA, 0x1E});                    // shr rdx, 30
        e({0x48, 0x31, 0xD0});                          // xor rax, rdx
        e({0x49, 0x0F, 0xAF, 0xC3});                   // imul rax, r11
        e({0x49, 0xBB}); e.u64(kM2);
        e({0x48, 0x89, 0xC2});                          // mov rdx, rax
        e({0x48, 0xC1, 0xEA, 0x1B});                    // shr rdx, 27
        e({0x48, 0x31, 0xD0});                          // xor rax, rdx
        e({0x49, 0x0F, 0xAF, 0xC3});                   // imul rax, r11
        e({0x48, 0x89, 0xC2});                          // mov rdx, rax
        e({0x48, 0xC1, 0xEA, 0x1F});                    // shr rdx, 31
        e({0x48, 0x31, 0xD0});                          // xor rax, rdx (eax = mask)
    };

    // xor dword [rbx+off], eax (auto disp8/disp32) — NO REX.B (that would make base=r11)
    auto xor_field = [&](uint32_t off) {
        if (off < 0x80) {
            e({0x33, 0x43, static_cast<uint8_t>(off)});
        } else {
            e({0x33, 0x83,
               static_cast<uint8_t>(off & 0xFF),
               static_cast<uint8_t>((off >> 8) & 0xFF),
               static_cast<uint8_t>((off >> 16) & 0xFF),
               static_cast<uint8_t>((off >> 24) & 0xFF)});
        }
    };

    // ---------------- prologue ----------------
    e({0x41, 0x54});                     // push r12
    e({0x41, 0x55});                     // push r13
    e({0x41, 0x56});                     // push r14
    e({0x41, 0x57});                     // push r15
    e({0x55});                           // push rbp
    e({0x48, 0x89, 0xE5});               // mov rbp, rsp
    e({0x48, 0x83, 0xE4, 0xF0});         // and rsp, -16
    e({0x48, 0x83, 0xEC, 0x30});         // sub rsp, 0x30

    // rbx = header (rip-relative to section start)
    e({0x48, 0x8D, 0x1D, 0, 0, 0, 0});   // lea rbx, [rip+hdr]
    e.patch32(e.c.size() - 4, -static_cast<int32_t>(kStage2Offset + e.c.size()));

    e({0x66, 0xC7, 0x43, 0x06, 0x00, 0x00}); // mov word [rbx+0x06], 0 (one-shot gate)

    e({0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00}); // mov rax, gs:[0x60]
    e({0x48, 0x8B, 0x70, 0x10});                                  // mov rsi, [rax+0x10]

    if (enable_anti_debug) {
        e({0x0F, 0xB6, 0x40, 0x02});                              // movzx eax, byte [rax+0x02]
        e({0x48, 0xC1, 0xE0, 0x0D});                              // shl rax, 13
        e({0x49, 0x89, 0xC1});                                    // mov r9, rax
        e({0x0F, 0xB6, 0x04, 0x25, 0xD4, 0x02, 0xFE, 0x7F});      // movzx eax, byte [0x7FFE02D4]
        e({0x83, 0xE0, 0x01});                                    // and eax, 1
        e({0x48, 0xC1, 0xE0, 0x11});                             // shl rax, 17
        e({0x49, 0x31, 0xC1});                                    // xor r9, rax
    } else {
        e({0x4D, 0x31, 0xC9});                                    // xor r9, r9
    }

    // Stage 1 (already executed) unlocked the image to RWX and stashed
    // VirtualProtect / LoadLibraryA / GetProcAddress in the scratch slots —
    // Stage 2 only needs to preserve the poison across LZSS flag clobbering.
    e({0x4C, 0x89, 0x8B, 0x88, 0x00, 0x00, 0x00});               // mov [rbx+kScrPoison], r9

    // ---------------- real_seed + handshake base + runtime magic ----------------
    e({0x4C, 0x8B, 0x73, 0x10});                                 // mov r14, [rbx+0x10] (pub_salt)
    e({0x49, 0x31, 0xF6});                                       // xor r14, rsi
    e({0x4C, 0x89, 0xC8});                                       // mov rax, r9
    e({0x49, 0x31, 0xF0});                                       // xor r14, rax (hb)

    e({0x49, 0xBB}); e.u64(secret_share);                        // mov r11, secret_share
    e({0x4D, 0x31, 0xCB});                                       // xor r11, r9
    e({0x4C, 0x8B, 0x7B, 0x10});                                 // mov r15, [rbx+0x10]
    e({0x4D, 0x31, 0xFB});                                       // xor r15, r11 (real_seed)

    e({0x48, 0x8B, 0x43, 0x10});                                 // mov rax, [rbx+0x10]
    e({0x48, 0x89, 0x43, 0x50});                                 // mov [rbx+kScrPubSalt], rax

    // M = splitmix64(hb); handoff magic low dword = compute_disk_header_magic(hb)
    e({0x4C, 0x89, 0xF0});                                       // mov rax, r14
    e({0x49, 0xBB}); e.u64(kGold64);
    e({0x4C, 0x01, 0xD8});                                       // add rax, r11
    e({0x49, 0xBB}); e.u64(kM1);
    e({0x48, 0x89, 0xC2});                                       // mov rdx, rax
    e({0x48, 0xC1, 0xEA, 0x1E});                                 // shr rdx, 30
    e({0x48, 0x31, 0xD0});                                       // xor rax, rdx
    e({0x49, 0x0F, 0xAF, 0xC3});                                 // imul rax, r11
    e({0x49, 0xBB}); e.u64(kM2);
    e({0x48, 0x89, 0xC2});                                       // mov rdx, rax
    e({0x48, 0xC1, 0xEA, 0x1B});                                 // shr rdx, 27
    e({0x48, 0x31, 0xD0});                                       // xor rax, rdx
    e({0x49, 0x0F, 0xAF, 0xC3});                                 // imul rax, r11
    e({0x48, 0x89, 0xC2});                                       // mov rdx, rax
    e({0x48, 0xC1, 0xEA, 0x1F});                                 // shr rdx, 31
    e({0x48, 0x31, 0xD0});                                       // xor rax, rdx (full M)
    e({0x35, 0xC5, 0xA3, 0xD9, 0x71});                           // xor eax, 0x71D9A3C5
    e({0x48, 0x89, 0x43, 0x58});                                 // mov [rbx+kScrMagicM], rax
    e({0x48, 0x89, 0x03});                                       // mov [rbx+0x00], rax (handoff magic)

    e({0x48, 0xC7, 0x43, 0x10, 0x00, 0x00, 0x00, 0x00});         // mov qword [rbx+0x10], 0 (wipe salt field)

    // ---------------- metadata trans-mask (disk: real_seed mask -> RAM: hb mask) ----------
    auto remask = [&](uint32_t off, uint32_t id) {
        mask32(false, id); xor_field(off);
        mask32(true,  id); xor_field(off);
    };
    remask(offsetof(VPackHeader, orig_pdata_rva),  kIdPdataRva);
    remask(offsetof(VPackHeader, orig_pdata_size), kIdPdataSize);
    remask(offsetof(VPackHeader, vcode_rva),       kIdVcodeRva);
    remask(offsetof(VPackHeader, vcode_size),      kIdVcodeSize);
    remask(offsetof(VPackHeader, vinit_rva),       kIdVinitRva);
    remask(offsetof(VPackHeader, vinit_size),      kIdVinitSize);

    // ---------------- region table masks ----------------
    mask32(false, kIdRegionM1);
    e({0x89, 0x43, kScrM1 & 0xFF});
    mask32(false, kIdRegionM2);
    e({0x89, 0x43, kScrM2 & 0xFF});
    mask32(false, kIdKeyMaskLo);
    e({0x89, 0x43, kScrKeyMask64 & 0xFF});
    mask32(false, kIdKeyMaskHi);
    e({0x48, 0xC1, 0xE0, 0x20});                                 // shl rax, 32
    e({0x48, 0x09, 0x43, kScrKeyMask64 & 0xFF});                 // or [rbx+kScrKeyMask64], rax

    e({0x49, 0xBB}); e.u64(kM1);                                  // mov r11, kM1 (chain constant)

    // r12 = blob base = start of the appended blob store (rip-lea; patched to relocs_end)
    e({0x4C, 0x8D, 0x25, 0, 0, 0, 0});                            // lea r12, [rip+blobs]
    out.fix_blobs_table = e.c.size() - 4;
    e({0x4C, 0x89, 0xA3, 0x90, 0x00, 0x00, 0x00});                // mov [rbx+kScrBlobBase], r12 (disp32!)

    // r8 = region table (rip-lea; patched after tables are appended)
    e({0x4C, 0x8D, 0x05, 0, 0, 0, 0});
    out.fix_regions_table = e.c.size() - 4;
    e({0xBA});
    for (int i = 0; i < 4; ++i) e.c.push_back(static_cast<uint8_t>((region_count >> (i * 8)) & 0xFF));

    // ---------------- region decode loop (chained cipher + LZSS) ----------------
    const size_t region_loop = e.c.size();
    e({0x85, 0xD2});                                             // test edx, edx
    fix_regions_done.push_back(e.jz32());
    e({0x41, 0x8B, 0x40, 0x04});                                 // mov eax, [r8+4] (masked orig size)
    e({0x33, 0x43, kScrM2 & 0xFF});                               // xor eax, [rbx+kScrM2] (NO REX.B!)
    e({0x89, 0xC1});                                             // mov ecx, eax
    e({0x41, 0x8B, 0x40, 0x10});                                 // mov eax, [r8+16] (masked blob offset)
    e({0x33, 0x43, kScrM2 & 0xFF});                               // xor eax, [rbx+kScrM2]
    e({0x4C, 0x8B, 0xA3, 0x90, 0x00, 0x00, 0x00});                 // mov r12, [rbx+kScrBlobBase] (disp32!)
    e({0x49, 0x01, 0xC4});                                       // add r12, rax (blob src = base + offset)
    e({0x41, 0x8B, 0x00});                                       // mov eax, [r8] (masked dest rva)
    e({0x33, 0x43, kScrM1 & 0xFF});                              // xor eax, [rbx+kScrM1]
    e({0x48, 0x89, 0xF7});                                       // mov rdi, rsi
    e({0x48, 0x01, 0xC7});                                       // add rdi, rax
    e({0x4D, 0x8B, 0x50, 0x08});                                 // mov r10, [r8+8] (masked key)
    e({0x4C, 0x33, 0x53, kScrKeyMask64 & 0xFF});                 // xor r10, [rbx+kScrKeyMask64]
    e({0x4C, 0x8B, 0x8B, 0x88, 0x00, 0x00, 0x00});               // mov r9, [rbx+0x88] (reload live poison)
    e({0x4D, 0x31, 0xCA});                                       // xor r10, r9 (anti-debug bind)
    e({0x31, 0xC0});                                             // xor eax, eax
    e({0x49, 0x89, 0x00});                                       // mov [r8], rax (wipe entry)
    e({0x49, 0x89, 0x40, 0x08});                                 // mov [r8+8], rax
    e({0x49, 0x89, 0x40, 0x10});                                 // mov [r8+16], rax
    e({0x85, 0xC9});                                             // test ecx, ecx
    fix_next_region.push_back(e.jz32());                         // jz next_region (rel32 — body is >127 bytes!)

    const size_t chunk_lbl = e.c.size();
    // Chained-decrypt the noise byte (pack-side chained_encrypt covers noise+flag too!)
    e({0x49, 0xC1, 0xC2, 0x0D});                                 // rol r10, 13
    e({0x4D, 0x0F, 0xAF, 0xD3});                                 // imul r10, r11
    e({0x41, 0x8A, 0x04, 0x24});                                 // mov al, [r12] (enc noise)
    e({0x44, 0x30, 0xD0});                                       // xor al, r10b (plain noise)
    e({0x41, 0x02, 0xC2});                                       // add r10b, al (plain feedback)
    e({0x49, 0xFF, 0xC4});                                       // inc r12
    e({0x3C, 0x01});                                             // cmp al, 1 (plaintext terminator)
    fix_next_region.push_back(e.jz32());                         // je next_region (rel32)
    // Chained-decrypt the flag byte
    e({0x49, 0xC1, 0xC2, 0x0D});                                 // rol r10, 13
    e({0x4D, 0x0F, 0xAF, 0xD3});                                 // imul r10, r11
    e({0x41, 0x8A, 0x04, 0x24});                                 // mov al, [r12] (enc flag)
    e({0x44, 0x30, 0xD0});                                       // xor al, r10b
    e({0x41, 0x02, 0xC2});                                       // add r10b, al
    e({0x49, 0xFF, 0xC4});                                       // inc r12
    e({0x41, 0x88, 0xC1});                                       // mov r9b, al (plaintext flags)
    e({0xC7, 0x44, 0x24, 0x28, 0x08, 0x00, 0x00, 0x00});         // mov dword [rsp+0x28], 8

    const size_t token_lbl = e.c.size();
    e({0x85, 0xC9});                                             // test ecx, ecx
    fix_next_region.push_back(e.jz32());                         // je next_region (rel32)
    e({0x41, 0xF6, 0xC1, 0x01});                                 // test r9b, 1
    const size_t jz_match = e.fwd8(); e({0x74, 0x00});

    // literal path
    e({0x49, 0xC1, 0xC2, 0x0D});                                 // rol r10, 13
    e({0x4D, 0x0F, 0xAF, 0xD3});                                 // imul r10, r11
    e({0x41, 0x8A, 0x04, 0x24});                                 // mov al, [r12]
    e({0x44, 0x30, 0xD0});                                       // xor al, r10b
    e({0x41, 0x02, 0xC2});                                       // add r10b, al (plain feedback)
    e({0x49, 0xFF, 0xC4});                                       // inc r12
    e({0x88, 0x07});                                             // mov [rdi], al
    e({0x48, 0xFF, 0xC7});                                       // inc rdi
    e({0xFF, 0xC9});                                             // dec ecx
    const size_t jmp_tokend = e.fwd8(); e({0xEB, 0x00});

    // match path
    const size_t do_match = e.c.size();
    e.set8(jz_match, do_match);
    e({0x49, 0xC1, 0xC2, 0x0D});                                 // rol r10, 13
    e({0x4D, 0x0F, 0xAF, 0xD3});                                 // imul r10, r11
    e({0x41, 0x8A, 0x14, 0x24});                                 // mov dl, [r12] (len-4)
    e({0x44, 0x30, 0xD2});                                       // xor dl, r10b
    e({0x41, 0x02, 0xD2});                                       // add r10b, dl
    e({0x49, 0xFF, 0xC4});                                       // inc r12
    e({0x49, 0xC1, 0xC2, 0x0D});                                 // rol r10, 13
    e({0x4D, 0x0F, 0xAF, 0xD3});                                 // imul r10, r11
    e({0x41, 0x8A, 0x04, 0x24});                                 // mov al, [r12] (dist lo)
    e({0x44, 0x30, 0xD0});                                       // xor al, r10b
    e({0x41, 0x02, 0xC2});                                       // add r10b, al
    e({0x49, 0xFF, 0xC4});                                       // inc r12
    e({0x44, 0x0F, 0xB6, 0xD8});                                 // movzx r13d, al (dist lo — REX.R for r13d; 41 made it ebx!)
    e({0x49, 0xC1, 0xC2, 0x0D});                                 // rol r10, 13
    e({0x4D, 0x0F, 0xAF, 0xD3});                                 // imul r10, r11
    e({0x41, 0x8A, 0x04, 0x24});                                 // mov al, [r12] (dist hi)
    e({0x44, 0x30, 0xD0});                                       // xor al, r10b
    e({0x41, 0x02, 0xC2});                                       // add r10b, al
    e({0x49, 0xFF, 0xC4});                                       // inc r12
    e({0x0F, 0xB6, 0xC0});                                       // movzx eax, al
    e({0xC1, 0xE0, 0x08});                                       // shl eax, 8
    e({0x41, 0x09, 0xC5});                                       // or r13d, eax (dist)
    e({0x0F, 0xB6, 0xD2});                                       // movzx edx, dl
    e({0x83, 0xC2, 0x04});                                       // add edx, 4 (len)
    e({0x2B, 0xCA});                                             // sub ecx, edx
    e({0x49, 0xF7, 0xDD});                                       // neg r13
    const size_t copy_lbl = e.c.size();
    e({0x42, 0x8A, 0x04, 0x2F});                                 // mov al, [rdi+r13]
    e({0x88, 0x07});                                             // mov [rdi], al
    e({0x48, 0xFF, 0xC7});                                       // inc rdi
    e({0xFF, 0xCA});                                             // dec edx
    e.back8(0x75, copy_lbl);

    const size_t token_end = e.c.size();
    e.set8(jmp_tokend, token_end);
    e({0x41, 0xC0, 0xE9, 0x01});                                 // shr r9b, 1 (modrm E9 = /5 SHR; C9 was ROR!)
    e({0xFF, 0x4C, 0x24, 0x28});                                 // dec dword [rsp+0x28]
    e({0x0F, 0x85, 0, 0, 0, 0});                                 // jnz token (rel32) — 0F 85, NOT 0F 75!
    e.patch32(e.c.size() - 4, static_cast<int32_t>(token_lbl) - e.here());
    e({0xE9, 0, 0, 0, 0});                                       // jmp chunk (rel32)
    e.patch32(e.c.size() - 4, static_cast<int32_t>(chunk_lbl) - e.here());

    const size_t next_region = e.c.size();
    for (size_t pos : fix_next_region) {
        e.patch32(pos, static_cast<int32_t>(next_region) - static_cast<int32_t>(pos + 4));
    }
    e({0x49, 0x83, 0xC0, 0x18});                                 // add r8, 0x18
    e({0xFF, 0xCA});                                             // dec edx
    e({0xE9, 0, 0, 0, 0});                                       // jmp region_loop
    e.patch32(e.c.size() - 4, static_cast<int32_t>(region_loop) - e.here());
    const size_t regions_done = e.c.size();
    for (size_t pos : fix_regions_done) e.patch32(pos, static_cast<int32_t>(regions_done) - static_cast<int32_t>(pos + 4));

    // ---------------- deferred relocations ----------------
    mask32(false, kIdRelocMask);
    e({0x89, 0x43, kScrRelocMask & 0xFF});                       // mov [rbx+kScrRelocMask], eax
    e({0x48, 0x89, 0xF2});                                       // mov rdx, rsi
    e({0x48, 0x2B, 0x53, 0x18});                                 // sub rdx, [rbx+0x18] (delta)
    e({0xB9});
    for (int i = 0; i < 4; ++i) e.c.push_back(static_cast<uint8_t>((reloc_count >> (i * 8)) & 0xFF));
    e({0x85, 0xC9});                                             // test ecx, ecx
    fix_reloc_done.push_back(e.jz32());
    e({0x4C, 0x8D, 0x05, 0, 0, 0, 0});                           // lea r8, [rip+relocs]
    out.fix_relocs_table = e.c.size() - 4;
    const size_t reloc_loop = e.c.size();
    e({0x41, 0x8B, 0x00});                                       // mov eax, [r8] (masked rva)
    e({0x41, 0xC7, 0x00, 0x00, 0x00, 0x00, 0x00});               // mov dword [r8], 0 (wipe)
    e({0x33, 0x43, kScrRelocMask & 0xFF});                       // xor eax, [rbx+kScrRelocMask]
    e({0x48, 0x01, 0x14, 0x06});                                 // add qword [rsi+rax], rdx
    e({0x49, 0x83, 0xC0, 0x04});                                 // add r8, 4
    e({0xFF, 0xC9});                                             // dec ecx
    e.back8(0x75, reloc_loop);
    const size_t reloc_done = e.c.size();
    for (size_t pos : fix_reloc_done) e.patch32(pos, static_cast<int32_t>(reloc_done) - static_cast<int32_t>(pos + 4));

    // ---------------- live .vcode re-encryption (runtime entropy — L1 killer) ------------
    mask32(true, kIdVcodeRva);
    e({0x44, 0x8B, 0xA3, 0xF0, 0x08, 0x00, 0x00});               // mov r12d, [rbx+0x8F0]
    e({0x41, 0x31, 0xE4});                                       // xor r12d, eax
    e({0x48, 0x89, 0xF7});                                       // mov rdi, rsi
    e({0x4C, 0x01, 0xE7});                                       // add rdi, r12
    mask32(true, kIdVcodeSize);
    e({0x8B, 0x8B, 0xF4, 0x08, 0x00, 0x00});                     // mov ecx, [rbx+0x8F4]
    e({0x31, 0xC8});                                             // xor ecx, eax
    e({0x85, 0xC9});                                             // test ecx, ecx
    fix_skip_live.push_back(e.jz32());
    e({0x0F, 0x31});                                             // rdtsc
    e({0x49, 0x89, 0xC2});                                       // mov r10, rax
    e({0x4C, 0x33, 0x14, 0x25, 0x08, 0x00, 0xFE, 0x7F});          // xor r10, [0x7FFE0008]
    e({0x4D, 0x31, 0xFA});                                       // xor r10, r15
    e({0x4D, 0x31, 0xF2});                                       // xor r10, r14 (K_live)
    e({0x49, 0xBB}); e.u64(kM1);
    e({0x48, 0xB8}); e.u64(kM2);
    e({0x48, 0x89, 0x43, kScrStreamM2 & 0xFF});                  // mov [rbx+kScrStreamM2], rax
    const size_t live_loop = e.c.size();
    e({0x49, 0xC1, 0xCA, 0x11});                                 // ror r10, 17
    e({0x4D, 0x0F, 0xAF, 0xD3});                                 // imul r10, r11
    e({0x4C, 0x89, 0xD2});                                       // mov rdx, r10
    e({0x48, 0xC1, 0xEA, 0x1F});                                 // shr rdx, 31
    e({0x4C, 0x31, 0xD2});                                       // xor r10, rdx
    e({0x4C, 0x03, 0x53, kScrStreamM2 & 0xFF});                   // add r10, [rbx+kScrStreamM2]
    e({0x44, 0x88, 0xD0});                                       // mov al, r10b
    e({0x30, 0x07});                                             // xor [rdi], al
    e({0x48, 0xFF, 0xC7});                                       // inc rdi
    e({0xFF, 0xC9});                                             // dec ecx
    e.back8(0x75, live_loop);
    const size_t skip_live = e.c.size();
    for (size_t pos : fix_skip_live) e.patch32(pos, static_cast<int32_t>(skip_live) - static_cast<int32_t>(pos + 4));

    // stash masked K_live + pub_salt for the SDK
    e({0x48, 0x8B, 0x43, kScrPubSalt & 0xFF});                   // mov rax, [rbx+kScrPubSalt]
    e({0x49, 0xBB}); e.u64(kGold64);
    e({0x49, 0x0F, 0xAF, 0xC3});                                 // imul rax, r11
    e({0x49, 0xBB}); e.u64(kLiveKeySalt);
    e({0x4C, 0x01, 0xD8});                                       // add rax, r11
    e({0x48, 0xC1, 0xC0, 0x11});                                 // rol rax, 17
    e({0x49, 0x31, 0xC2});                                       // xor r10, rax (rm=r10 needs REX.B; 4C 31 C2 was 'xor rdx,rax')
    e({0x4C, 0x89, 0x93, 0xD8, 0x08, 0x00, 0x00});               // mov [rbx+kScrLiveVcodeKey], r10 (REX.R for r10 src)
    e({0x48, 0x8B, 0x43, kScrPubSalt & 0xFF});                   // mov rax, [rbx+kScrPubSalt]
    e({0x48, 0x89, 0x83, 0xD0, 0x08, 0x00, 0x00});               // mov [rbx+kScrPubSaltFinal], rax

    // ---------------- hashed IAT resolution ----------------
    mask32(false, kIdImportRva);
    e({0x44, 0x8B, 0x63, 0x24});                                 // mov r12d, [rbx+0x24] (masked desc rva)
    e({0x41, 0x31, 0xE4});                                       // xor r12d, eax
    e({0xC7, 0x43, 0x24, 0x00, 0x00, 0x00, 0x00});               // mov dword [rbx+0x24], 0
    e({0x4D, 0x85, 0xE4});                                       // test r12, r12
    fix_imp_done.push_back(e.jz32());
    e({0x49, 0x01, 0xF4});                                       // add r12, rsi (desc base; REX.W+B — 4C made reg=r14!)

    const size_t desc_loop = e.c.size();
    e({0x41, 0x8B, 0x44, 0x24, 0x0C});                           // mov eax, [r12+0x0C] (Name RVA)
    e({0x85, 0xC0});                                             // test eax, eax
    fix_imp_done.push_back(e.jz32());
    e({0x48, 0x89, 0xF1});                                       // mov rcx, rsi
    e({0x48, 0x01, 0xC1});                                       // add rcx, rax (dll name)
    e({0xFF, 0x93, 0x60, 0x00, 0x00, 0x00});                     // call [rbx+kScrLLA]
    e({0x48, 0x85, 0xC0});                                       // test rax, rax
    fix_imp_done.push_back(e.jz32());
    e({0x49, 0x89, 0xC5});                                       // mov r13, rax (hMod)

    e({0x41, 0x8B, 0x04, 0x24});                                 // mov eax, [r12+0x00] (OFT)
    e({0x85, 0xC0});                                             // test eax, eax
    const size_t jnz_oft = e.fwd8(); e({0x75, 0x00});
    e({0x41, 0x8B, 0x44, 0x24, 0x10});                           // mov eax, [r12+0x10] (FT fallback)
    const size_t use_oft = e.c.size();
    e.set8(jnz_oft, use_oft);
    e({0x48, 0x89, 0xF2});                                       // mov rdx, rsi
    e({0x48, 0x01, 0xC2});                                       // add rdx, rax (ilt)
    e({0x48, 0x89, 0x53, 0x78});                                 // mov [rbx+0x78], rdx (ilt — header scratch, NEVER inside callee shadow space)
    e({0x41, 0x8B, 0x44, 0x24, 0x10});                           // mov eax, [r12+0x10] (FT)
    e({0x48, 0x89, 0xF2});                                       // mov rdx, rsi
    e({0x48, 0x01, 0xC2});                                       // add rdx, rax (iat)
    e({0x48, 0x89, 0x93, 0x80, 0x00, 0x00, 0x00});               // mov [rbx+0x80], rdx (iat — header scratch)

    const size_t thunk_loop = e.c.size();
    e({0x48, 0x8B, 0x53, 0x78});                                 // mov rdx, [rbx+0x78] (ilt)
    e({0x48, 0x8B, 0x02});                                       // mov rax, [rdx] (*ilt)
    e({0x48, 0x85, 0xC0});                                       // test rax, rax
    std::vector<size_t> fix_next_desc;
    fix_next_desc.push_back(e.jz32());
    e({0x48, 0x31, 0xFF});                                       // xor rdi, rdi
    e({0x48, 0x0F, 0xBA, 0xE0, 0x3F});                           // bt rax, 63
    e({0x72, 0x0A});                                             // jc by_ordinal (+10)
    e({0x48, 0x8D, 0x3C, 0x06});                                 // lea rdi, [rsi+rax] (IBN)
    e({0x48, 0x8D, 0x57, 0x02});                                 // lea rdx, [rdi+2] (&Name)
    e({0xEB, 0x03});                                             // jmp do_getproc (+3)
    e({0x0F, 0xB7, 0xD0});                                       // by_ordinal: movzx edx, ax
    e({0x4C, 0x89, 0xE9});                                       // do_getproc: mov rcx, r13
    e({0xFF, 0x93, 0x68, 0x00, 0x00, 0x00});                     // call [rbx+kScrGPA]
    e({0x48, 0x8B, 0x53, 0x78});                                 // mov rdx, [rbx+0x78] (ilt)
    e({0x48, 0xC7, 0x02, 0x00, 0x00, 0x00, 0x00});               // mov qword [rdx], 0 (wipe ILT)
    e({0x48, 0x8B, 0x93, 0x80, 0x00, 0x00, 0x00});               // mov rdx, [rbx+0x80] (iat)
    e({0x48, 0x89, 0x02});                                       // mov [rdx], rax (*iat = proc)
    e({0x48, 0x85, 0xFF});                                       // test rdi, rdi
    e({0x74, 0x16});                                             // jz skip_fn_wipe (+22)
    e({0x66, 0xC7, 0x07, 0x00, 0x00});                           // mov word [rdi], 0 (Hint)
    e({0x48, 0x83, 0xC7, 0x02});                                 // add rdi, 2
    const size_t wipe_fn = e.c.size();
    e({0x80, 0x3F, 0x00});                                       // cmp byte [rdi], 0
    e({0x74, 0x08});                                             // jz skip_fn_wipe
    e({0xC6, 0x07, 0x00});                                       // mov byte [rdi], 0
    e({0x48, 0xFF, 0xC7});                                       // inc rdi
    e.back8(0xEB, wipe_fn);
    const size_t skip_fn_wipe = e.c.size();
    (void)skip_fn_wipe;
    e({0x48, 0x83, 0x43, 0x78, 0x08});                           // add qword [rbx+0x78], 8
    e({0x48, 0x83, 0x83, 0x80, 0x00, 0x00, 0x00, 0x08});         // add qword [rbx+0x80], 8
    e({0xE9, 0, 0, 0, 0});                                       // jmp thunk_loop
    e.patch32(e.c.size() - 4, static_cast<int32_t>(thunk_loop) - e.here());

    const size_t next_desc = e.c.size();
    for (size_t pos : fix_next_desc) e.patch32(pos, static_cast<int32_t>(next_desc) - static_cast<int32_t>(pos + 4));
    e({0x41, 0x8B, 0x44, 0x24, 0x0C});                           // mov eax, [r12+0x0C]
    e({0x48, 0x89, 0xF7});                                       // mov rdi, rsi
    e({0x48, 0x01, 0xC7});                                       // add rdi, rax (dll name)
    const size_t wipe_dll = e.c.size();
    e({0x80, 0x3F, 0x00});                                       // cmp byte [rdi], 0
    e({0x74, 0x08});                                             // jz skip_dll_wipe
    e({0xC6, 0x07, 0x00});                                       // mov byte [rdi], 0
    e({0x48, 0xFF, 0xC7});                                       // inc rdi
    e.back8(0xEB, wipe_dll);
    const size_t skip_dll = e.c.size();
    (void)skip_dll;
    e({0x31, 0xC0});                                             // xor eax, eax
    e({0x41, 0x89, 0x04, 0x24});                                 // mov [r12+0x00], eax
    e({0x41, 0x89, 0x44, 0x24, 0x04});                           // mov [r12+0x04], eax
    e({0x41, 0x89, 0x44, 0x24, 0x08});                           // mov [r12+0x08], eax
    e({0x41, 0x89, 0x44, 0x24, 0x0C});                           // mov [r12+0x0C], eax
    e({0x41, 0x89, 0x44, 0x24, 0x10});                           // mov [r12+0x10], eax
    e({0x49, 0x83, 0xC4, 0x14});                                 // add r12, 20
    e({0xE9, 0, 0, 0, 0});                                       // jmp desc_loop
    e.patch32(e.c.size() - 4, static_cast<int32_t>(desc_loop) - e.here());

    const size_t imp_done = e.c.size();
    for (size_t pos : fix_imp_done) e.patch32(pos, static_cast<int32_t>(imp_done) - static_cast<int32_t>(pos + 4));
    e({0x48, 0xC7, 0x43, 0x60, 0x00, 0x00, 0x00, 0x00});         // wipe LLA
    e({0x48, 0xC7, 0x43, 0x68, 0x00, 0x00, 0x00, 0x00});         // wipe GPA
    e({0x48, 0xC7, 0x43, 0x70, 0x00, 0x00, 0x00, 0x00});         // wipe VP

    // ---------------- TLS replay pair + EpStub handoff + bridge ----------------
    // The original TLS callbacks are replayed by EpStub AFTER the full unpack
    // (running them inside a loader TLS callback proved fatal across CRTs), so
    // Stage 2 simply publishes their RVAs into the handoff slot.
    e({0x48, 0xB8}); e.u64(tls_cb_pair);                          // mov rax, cb0_rva | (cb1_rva << 32)
    e({0x48, 0x89, 0x83, 0xE0, 0x08, 0x00, 0x00});               // mov [rbx+kScrTlsCbPair], rax

    e({0x8B, 0x43, kScrMagicM & 0xFF});                          // mov eax, [rbx+kScrMagicM] (M_lo)
    e({0x89, 0x43, 0x10});                                       // mov [rbx+0x10], eax
    e({0x35});
    for (int i = 0; i < 4; ++i) e.c.push_back(static_cast<uint8_t>((bridge_rva >> (i * 8)) & 0xFF)); // xor eax, bridge_rva
    e({0x89, 0x43, 0x0C});                                       // mov [rbx+0x0C], eax (EpStub unmask data)

    e({0x48, 0x89, 0xF7});                                       // mov rdi, rsi
    e({0xB8});
    for (int i = 0; i < 4; ++i) e.c.push_back(static_cast<uint8_t>((bridge_rva >> (i * 8)) & 0xFF)); // mov eax, bridge_rva
    e({0x48, 0x01, 0xC7});                                       // add rdi, rax (bridge VA)
    e({0x4C, 0x89, 0xFA});                                       // mov r10, r15
    e({0x49, 0xBB}); e.u64(kBridgeSalt);
    e({0x4D, 0x31, 0xDA});                                       // xor r10, r11
    e({0x4C, 0x8B, 0x8B, 0x88, 0x00, 0x00, 0x00});               // mov r9, [rbx+0x88] (reload live poison)
    e({0x4D, 0x31, 0xCA});                                       // xor r10, r9 (anti-debug bind)
    e({0x49, 0xBB}); e.u64(kM1);
    e({0xB9, 0x40, 0x00, 0x00, 0x00});                           // mov ecx, kStolenOepSpan
    const size_t bridge_loop = e.c.size();
    e({0x49, 0xC1, 0xC2, 0x0D});                                 // rol r10, 13
    e({0x4D, 0x0F, 0xAF, 0xD3});                                 // imul r10, r11
    e({0x44, 0x88, 0xD0});                                       // mov al, r10b
    e({0x30, 0x07});                                             // xor [rdi], al
    e({0x44, 0x02, 0x17});                                       // add r10b, [rdi] (plain feedback)
    e({0x48, 0xFF, 0xC7});                                       // inc rdi
    e({0xFF, 0xC9});                                             // dec ecx
    e.back8(0x75, bridge_loop);

    // ---------------- final wipes + epilogue ----------------
    // Wipe FLAGS only (dword at +0x08). MUST NOT wipe +0x0C/+0x10/+0x14 —
    // EpStub and TlsStub still need those handoff values after Stage 2 returns!
    e({0xC7, 0x43, 0x08, 0x00, 0x00, 0x00, 0x00});              // mov dword [rbx+0x08], 0
    e({0x48, 0x8D, 0x7B, 0x30});                                 // lea rdi, [rbx+0x30]
    e({0xB9});
    for (int i = 0; i < 4; ++i) e.c.push_back(static_cast<uint8_t>((kLegacyWipeLen >> (i * 8)) & 0xFF));
    e({0x31, 0xC0});                                             // xor eax, eax
    e({0xF3, 0xAA});                                             // rep stosb

    // kScrPubSaltFinal / kScrLiveVcodeKey / kScrTlsCbPair (0x8D0+) were stashed
    // earlier and sit past kLegacyWipeLen — they survive this wipe intact.

    e({0x48, 0x89, 0xEC});                                       // mov rsp, rbp
    e({0x5D});                                                   // pop rbp
    e({0x41, 0x5F});                                             // pop r15
    e({0x41, 0x5E});                                             // pop r14
    e({0x41, 0x5D});                                             // pop r13
    e({0x41, 0x5C});                                             // pop r12
    e({0xC3});                                                   // ret

    out.code = std::move(e.c);
    return out;
}

// ============================================================================
// Stage 1 emitter: CRC-gate over EpStub+TlsStub, decrypt Stage 2, call it,
// then wipe Stage 2 code + tables + blobs. Idempotent (region_count gate).
// ============================================================================
std::vector<uint8_t> emit_stage1(
    uint32_t stage2_code_size,
    uint32_t wipe_len,
    uint8_t  stage2_key,
    uint8_t  s1_rol,
    uint8_t  s1_add,
    uint8_t  s1_xor,
    uint32_t stub_crc32,
    bool     enable_anti_debug
) {
    CodeBuf e;

    e({0x51});                       // push rcx
    e({0x52});                       // push rdx
    e({0x41, 0x50});                 // push r8
    e({0x41, 0x51});                 // push r9
    e({0x53});                       // push rbx
    e({0x56});                       // push rsi
    e({0x57});                       // push rdi
    e({0x41, 0x54});                 // push r12
    e({0x41, 0x55});                 // push r13
    e({0x41, 0x56});                 // push r14
    e({0x41, 0x57});                 // push r15
    e({0x55});                       // push rbp
    e({0x48, 0x89, 0xE5});           // mov rbp, rsp
    e({0x48, 0x83, 0xE4, 0xF0});     // and rsp, -16
    e({0x48, 0x83, 0xEC, 0x40});     // sub rsp, 0x40 (shadow + scratch incl [rsp+0x30]/[rsp+0x38])

    e({0x31, 0xC0, 0x74, 0x01, 0xE8}); // opaque predicate (xor eax,eax; jz +1; db E8)

    e({0x48, 0x8D, 0x1D, 0, 0, 0, 0}); // lea rbx, [rip+hdr]
    e.patch32(e.c.size() - 4, -static_cast<int32_t>(kStage1Offset + e.c.size()));

    std::vector<size_t> fix_s1_done;

    // CRC gate over [hdr+0xA00 .. hdr+0xB00)
    e({0x48, 0x8D, 0xB3, 0x00, 0x0A, 0x00, 0x00});  // lea rsi, [rbx+0xA00]
    e({0xB9, 0x00, 0x01, 0x00, 0x00});              // mov ecx, 0x100
    e({0xB8, 0xFF, 0xFF, 0xFF, 0xFF});              // mov eax, 0xFFFFFFFF
    const size_t crc_byte = e.c.size();
    e({0x0F, 0xB6, 0x16});                          // movzx edx, byte [rsi]
    e({0x31, 0xD0});                                // xor eax, edx
    e({0x41, 0xB8, 0x08, 0x00, 0x00, 0x00});        // mov r8d, 8
    const size_t crc_bit = e.c.size();
    e({0xD1, 0xE8});                                // shr eax, 1
    e({0x1B, 0xD2});                                // sbb edx, edx (opcode 1B = SBB r32,r/m32; 2B was SUB!)
    e({0x81, 0xE2, 0x20, 0x83, 0xB8, 0xED});        // and edx, 0xEDB88320
    e({0x31, 0xD0});                                // xor eax, edx
    e({0x41, 0xFF, 0xC8});                          // dec r8d
    e.back8(0x75, crc_bit);
    e({0x48, 0xFF, 0xC6});                          // inc rsi
    e({0xFF, 0xC9});                                // dec ecx
    e.back8(0x75, crc_byte);
    e({0xF7, 0xD0});                                // not eax
    e({0x3D});
    for (int i = 0; i < 4; ++i) e.c.push_back(static_cast<uint8_t>((stub_crc32 >> (i * 8)) & 0xFF));
    e({0x74, 0x02});                                // je crc_ok
    e({0x0F, 0x0B});                                // ud2 (tamper -> hard crash)
    // crc_ok: one-shot gate
    e({0x0F, 0xB7, 0x53, 0x06});                    // movzx edx, word [rbx+0x06] (region_count)
    e({0x85, 0xD2});                                // test edx, edx
    fix_s1_done.push_back(e.jz32());

    // ---------------- PEB->Ldr kernelbase walk (FNV-1a-ci BaseDllName) ----------------
    e({0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00}); // mov rax, gs:[0x60]
    e({0x48, 0x8B, 0x70, 0x10});                                 // mov rsi, [rax+0x10] (ImageBase)
    e({0x48, 0x8B, 0x40, 0x18});                                 // mov rax, [rax+0x18] (Ldr)
    e({0x48, 0x8B, 0x48, 0x10});                                 // mov rcx, [rax+0x10] (InLoadOrder head)
    e({0x48, 0x89, 0x4C, 0x24, 0x20});                           // mov [rsp+0x20], rcx (head)
    const size_t mod_loop = e.c.size();
    e({0x4C, 0x8B, 0x41, 0x60});                                 // mov r8, [rcx+0x60] (BaseDllName.Buffer)
    e({0x4D, 0x85, 0xC0});                                       // test r8, r8
    const size_t jz_mod_next = e.fwd8(); e({0x74, 0x00});
    e({0x0F, 0xB7, 0x41, 0x58});                                 // movzx eax, word [rcx+0x58] (Length)
    e({0x48, 0x89, 0x44, 0x24, 0x28});                           // mov [rsp+0x28], rax (remaining chars)
    e({0x48, 0xB8}); e.u64(kFnvBasis);
    e({0x49, 0xBB}); e.u64(kFnvPrime);
    const size_t mod_name_loop = e.c.size();
    e({0x48, 0x83, 0x7C, 0x24, 0x28, 0x00});                     // cmp qword [rsp+0x28], 0
    const size_t jz_mod_namedone = e.fwd8(); e({0x74, 0x00});
    e({0x45, 0x0F, 0xB6, 0x10});                                 // movzx r10d, byte [r8]
    e({0x49, 0xFF, 0xC0});                                       // inc r8
    e({0x48, 0x83, 0x6C, 0x24, 0x28, 0x01});                     // sub qword [rsp+0x28], 1
    e({0x45, 0x84, 0xD2});                                       // test r10b, r10b
    e.back8(0x74, mod_name_loop);                                // jz loop (skip UTF-16LE zero high bytes!)
    e({0x41, 0x80, 0xFA, 0x41});                                 // cmp r10b, 'A'
    const size_t jb_lc = e.fwd8(); e({0x72, 0x00});
    e({0x41, 0x80, 0xFA, 0x5A});                                 // cmp r10b, 'Z'
    const size_t ja_lc = e.fwd8(); e({0x77, 0x00});
    e({0x41, 0x80, 0xC2, 0x20});                                 // add r10b, 0x20
    const size_t skip_lc = e.c.size();
    e.set8(jb_lc, skip_lc); e.set8(ja_lc, skip_lc);
    e({0x4C, 0x31, 0xD0});                                       // xor rax, r10
    e({0x49, 0x0F, 0xAF, 0xC3});                                 // imul rax, r11
    e.back8(0xEB, mod_name_loop);
    const size_t mod_namedone = e.c.size();
    e.set8(jz_mod_namedone, mod_namedone);
    e({0x49, 0xBB}); e.u64(kHashKernelBase);
    e({0x4C, 0x39, 0xD8});                                       // cmp rax, r11
    const size_t je_found = e.fwd8(); e({0x74, 0x00});
    const size_t mod_next = e.c.size();
    e.set8(jz_mod_next, mod_next);
    e({0x48, 0x8B, 0x09});                                       // mov rcx, [rcx]
    e({0x48, 0x3B, 0x4C, 0x24, 0x20});                           // cmp rcx, [rsp+0x20]
    e({0x0F, 0x85, 0, 0, 0, 0});                                 // jne mod_loop
    e.patch32(e.c.size() - 4, static_cast<int32_t>(mod_loop) - e.here());
    e({0x45, 0x31, 0xED});                                       // xor r13d, r13d (not found)
    const size_t jmp_after_walk = e.fwd8(); e({0xEB, 0x00});
    const size_t mod_found = e.c.size();
    e.set8(je_found, mod_found);
    e({0x4C, 0x8B, 0x69, 0x30});                                 // mov r13, [rcx+0x30] (DllBase)
    const size_t after_walk = e.c.size();
    e.set8(jmp_after_walk, after_walk);

    // ---------------- kernel32 export walk (VP / LLA / GPA by hash) ----------------
    e({0x4D, 0x85, 0xED});                                       // test r13, r13
    fix_s1_done.push_back(e.jz32());                            // jz s1_done (fails safe)

    e({0x41, 0x8B, 0x45, 0x3C});                                 // mov eax, [r13+0x3C]
    e({0x4C, 0x89, 0xEA});                                       // mov rdx, r13
    e({0x48, 0x01, 0xC2});                                       // add rdx, rax (nt)
    e({0x8B, 0x8A, 0x88, 0x00, 0x00, 0x00});                     // mov ecx, [rdx+0x88] (export RVA)
    e({0x48, 0x89, 0xC8});                                       // mov rax, rcx
    e({0x4C, 0x89, 0xEA});                                       // mov rdx, r13
    e({0x48, 0x01, 0xC2});                                       // add rdx, rax (expdir)
    e({0x49, 0x89, 0xD4});                                       // mov r12, rdx (expdir)
    e({0x41, 0x8B, 0x4C, 0x24, 0x18});                           // mov ecx, [r12+0x18] (NumberOfNames)
    e({0x41, 0x8B, 0x44, 0x24, 0x20});                           // mov eax, [r12+0x20] (names RVA)
    e({0x4C, 0x89, 0xEA});                                       // mov rdx, r13
    e({0x48, 0x01, 0xC2});                                       // add rdx, rax
    e({0x49, 0x89, 0xD6});                                       // mov r14, rdx (names base — NEVER r10: the hash loop clobbers r10!)
    e({0x41, 0x8B, 0x44, 0x24, 0x24});                           // mov eax, [r12+0x24] (ords RVA)
    e({0x4D, 0x89, 0xE9});                                       // mov r9, r13 (REX.R+B)
    e({0x49, 0x01, 0xC1});                                       // add r9, rax (ords base; REX.W+B — 4C made reg=r8!)
    e({0x41, 0x8B, 0x44, 0x24, 0x1C});                           // mov eax, [r12+0x1C] (funcs RVA)
    e({0x4C, 0x89, 0xEA});                                       // mov rdx, r13
    e({0x48, 0x01, 0xC2});                                       // add rdx, rax (funcs base)
    e({0x48, 0x89, 0x54, 0x24, 0x20});                           // mov [rsp+0x20], rdx
    e({0x48, 0xC7, 0x44, 0x24, 0x28, 0, 0, 0, 0});               // mov qword [rsp+0x28], 0 (idx)

    const size_t exp_loop = e.c.size();
    e({0x85, 0xC9});                                             // test ecx, ecx
    std::vector<size_t> fix_exp_done;
    fix_exp_done.push_back(e.jz32());
    e({0x48, 0x8B, 0x44, 0x24, 0x28});                           // mov rax, [rsp+0x28] (idx)
    e({0x41, 0x8B, 0x04, 0x86});                                 // mov eax, [r14+rax*4] (name RVA — r14 = names base)
    e({0x4C, 0x89, 0xEA});                                       // mov rdx, r13
    e({0x48, 0x01, 0xC2});                                       // add rdx, rax (name ptr)
    e({0x48, 0xB8}); e.u64(kFnvBasis);
    e({0x49, 0xBB}); e.u64(kFnvPrime);
    const size_t nh_loop = e.c.size();
    e({0x44, 0x0F, 0xB6, 0x12});                                 // movzx r10d, byte [rdx]
    e({0x45, 0x84, 0xD2});                                       // test r10b, r10b
    const size_t jz_nh_done = e.fwd8(); e({0x74, 0x00});
    e({0x41, 0x80, 0xFA, 0x41});                                 // cmp r10b, 'A'
    const size_t jb2 = e.fwd8(); e({0x72, 0x00});
    e({0x41, 0x80, 0xFA, 0x5A});                                 // cmp r10b, 'Z'
    const size_t ja2 = e.fwd8(); e({0x77, 0x00});
    e({0x41, 0x80, 0xC2, 0x20});                                 // add r10b, 0x20
    const size_t skip2 = e.c.size();
    e.set8(jb2, skip2); e.set8(ja2, skip2);
    e({0x4C, 0x31, 0xD0});                                       // xor rax, r10
    e({0x49, 0x0F, 0xAF, 0xC3});                                 // imul rax, r11
    e({0x48, 0xFF, 0xC2});                                       // inc rdx
    e.back8(0xEB, nh_loop);
    const size_t nh_done = e.c.size();
    e.set8(jz_nh_done, nh_done);

    e({0x49, 0xBB}); e.u64(kHashVirtualProtect);
    e({0x4C, 0x39, 0xD8});                                       // cmp rax, r11
    const size_t je_vp = e.fwd8(); e({0x74, 0x00});
    e({0x49, 0xBB}); e.u64(kHashLoadLibraryA);
    e({0x4C, 0x39, 0xD8});
    const size_t je_lla = e.fwd8(); e({0x74, 0x00});
    e({0x49, 0xBB}); e.u64(kHashGetProcAddr);
    e({0x4C, 0x39, 0xD8});
    const size_t je_gpa = e.fwd8(); e({0x74, 0x00});
    const size_t jmp_exp_next = e.fwd8(); e({0xEB, 0x00});

    auto emit_store = [&](int mode) {
        e({0x48, 0x8B, 0x44, 0x24, 0x28});                       // mov rax, [rsp+0x28] (idx)
        e({0x66, 0x41, 0x8B, 0x04, 0x41});                        // mov cx, [r9+rax*2] (ordinal)
        e({0x0F, 0xB7, 0xC1});                                   // movzx eax, cx
        e({0x41, 0x8B, 0x54, 0x24, 0x10});                        // mov edx, [r12+0x10] (IMAGE_EXPORT_DIRECTORY.Base!)
        e({0x2B, 0xC2});                                         // sub eax, edx (funcs index = ordinal - Base)
        e({0x48, 0x8B, 0x54, 0x24, 0x20});                       // mov rdx, [rsp+0x20] (funcs)
        e({0x8B, 0x04, 0x82});                                   // mov eax, [rdx+rax*4] (fn RVA)
        e({0x4C, 0x89, 0xEA});                                   // mov rdx, r13
        e({0x48, 0x01, 0xC2});                                   // add rdx, rax (fn VA)
        if (mode == 0) {
            e({0x49, 0x89, 0xD7});                               // mov r15, rdx (VirtualProtect — image still RX, no header writes yet!)
        } else if (mode == 1) {
            e({0x48, 0x89, 0x54, 0x24, 0x30});                   // mov [rsp+0x30], rdx (LoadLibraryA)
        } else {
            e({0x48, 0x89, 0x54, 0x24, 0x38});                   // mov [rsp+0x38], rdx (GetProcAddress)
        }
    };
    const size_t store_vp = e.c.size();
    e.set8(je_vp, store_vp);
    emit_store(0);
    const size_t jmp_vp_next = e.fwd8(); e({0xEB, 0x00});
    const size_t store_lla = e.c.size();
    e.set8(je_lla, store_lla);
    emit_store(1);
    const size_t jmp_lla_next = e.fwd8(); e({0xEB, 0x00});
    const size_t store_gpa = e.c.size();
    e.set8(je_gpa, store_gpa);
    emit_store(2);
    const size_t exp_next = e.c.size();
    e.set8(jmp_exp_next, exp_next);
    e.set8(jmp_vp_next, exp_next);
    e.set8(jmp_lla_next, exp_next);
    e({0x48, 0x83, 0x44, 0x24, 0x28, 0x01});                     // add qword [rsp+0x28], 1
    e({0xFF, 0xC9});                                             // dec ecx
    e({0x0F, 0x85, 0, 0, 0, 0});                                 // jnz exp_loop
    e.patch32(e.c.size() - 4, static_cast<int32_t>(exp_loop) - e.here());
    const size_t exp_done = e.c.size();
    for (size_t pos : fix_exp_done) e.patch32(pos, static_cast<int32_t>(exp_done) - static_cast<int32_t>(pos + 4));

    // ---------------- unlock the STUB SECTION FIRST (it is RX at load; every header-slot
    // write below — and Stage 2's self-decrypt/wipe — needs it writable), then every
    // committed section (per-section; one giant span fails with ERROR_INVALID_PARAMETER
    // because DISCARDABLE sections are decommitted at load).
    e({0x4D, 0x85, 0xFF});                                       // test r15, r15 (VirtualProtect resolved?)
    fix_s1_done.push_back(e.jz32());                             // je s1_done (fails safe)
    // NOTE: the stub section is marked RWX ON DISK (UPX-style) so no self-unlock call is
    // needed here — kernelbase FAST-FAILs (0x57 self-modify guard) when a caller changes
    // the protection of the page its own return address lives in!

    e({0x8B, 0x46, 0x3C});                                        // mov eax, [rsi+0x3C] (e_lfanew — 32-BIT read! 48 8B pulled DOS-junk high bits)
    e({0x49, 0x89, 0xF4});                                       // mov r12, rsi (REX.B — 4C 89 F4 was 'mov rsp, r14'!!)
    e({0x49, 0x01, 0xC4});                                       // add r12, rax (nt headers)
    e({0x41, 0x0F, 0xB7, 0x44, 0x24, 0x06});                     // movzx eax, word [r12+0x06] (NumberOfSections)
    e({0x48, 0x89, 0x44, 0x24, 0x28});                           // mov [rsp+0x28], rax (counter — idx slot is dead after the walk)
    e({0x4D, 0x8D, 0xB4, 0x24, 0x08, 0x01, 0x00, 0x00});         // lea r14, [r12+0x108] (section table)

    const size_t sec_loop = e.c.size();
    e({0x83, 0x7C, 0x24, 0x28, 0x00});                           // cmp dword [rsp+0x28], 0
    std::vector<size_t> fix_sec_done;
    fix_sec_done.push_back(e.jz32());
    e({0x41, 0x8B, 0x44, 0x26, 0x08});                           // mov eax, [r14+8] (VirtualSize)
    e({0x41, 0x8B, 0x54, 0x26, 0x10});                           // mov edx, [r14+16] (SizeOfRawData)
    e({0x39, 0xD0});                                             // cmp eax, edx
    const size_t jae_use_vs = e.fwd8(); e({0x73, 0x00});
    e({0x89, 0xD0});                                             // mov eax, edx
    const size_t use_vs = e.c.size();
    e.set8(jae_use_vs, use_vs);
    e({0x85, 0xC0});                                             // test eax, eax (size)
    const size_t jz_next_sec = e.fwd8(); e({0x74, 0x00});
    e({0x41, 0x81, 0x7C, 0x26, 0x24, 0x00, 0x00, 0x02, 0x00});   // cmp dword [r14+0x24], 0x02000000 (DISCARDABLE; REX.B + full imm32!)
    const size_t jnz_skip_discard = e.fwd8(); e({0x75, 0x00});
    e({0x48, 0x89, 0xC2});                                       // mov rdx, rax (dwSize)
    e({0x48, 0x89, 0xF1});                                       // mov rcx, rsi (ImageBase)
    e({0x41, 0x8B, 0x44, 0x26, 0x0C});                           // mov eax, [r14+12] (VirtualAddress)
    e({0x48, 0x01, 0xC1});                                       // add rcx, rax (lpAddress)
    e({0x41, 0xB8, 0x40, 0x00, 0x00, 0x00});                     // mov r8d, PAGE_EXECUTE_READWRITE
    e({0x4C, 0x8D, 0x4C, 0x24, 0x20});                           // lea r9, [rsp+0x20]
    e({0x48, 0x89, 0x4B, 0x28});                                 // mov [rbx+0x28], rcx (MARK: current section VA)
    e({0x41, 0xFF, 0xD7});                                       // call r15 (VirtualProtect — failures ignored)
    const size_t next_sec = e.c.size();
    e.set8(jz_next_sec, next_sec);
    e.set8(jnz_skip_discard, next_sec);                           // DISCARDABLE sections are decommitted — skip!
    e({0x49, 0x83, 0xC6, 0x28});                                 // add r14, 40
    e({0xFF, 0x4C, 0x24, 0x28});                                 // dec dword [rsp+0x28]
    e.jmp32_to(sec_loop);
    const size_t sec_done = e.c.size();
    for (size_t pos : fix_sec_done) e.patch32(pos, static_cast<int32_t>(sec_done) - static_cast<int32_t>(pos + 4));

    // Now every committed section is RWX: stash VP/LLA/GPA into the header scratch slots for Stage 2
    e({0x48, 0xC7, 0x43, 0x28, 0x22, 0x00, 0x00, 0x00});         // mov qword [rbx+0x28], 0x22 (MARK: loop done)
    e({0x4C, 0x89, 0xBB, 0x70, 0x00, 0x00, 0x00});               // mov [rbx+kScrVP], r15
    e({0x48, 0x8B, 0x44, 0x24, 0x30});                           // mov rax, [rsp+0x30] (LLA)
    e({0x48, 0x89, 0x43, 0x60});                                 // mov [rbx+kScrLLA], rax
    e({0x48, 0x8B, 0x44, 0x24, 0x38});                           // mov rax, [rsp+0x38] (GPA)
    e({0x48, 0x89, 0x43, 0x68});                                 // mov [rbx+kScrGPA], rax

    // decrypt Stage 2
    e({0x48, 0x8D, 0xBB, 0x80, 0x0E, 0x00, 0x00});  // lea rdi, [rbx+kStage2Offset]
    e({0xB9});
    for (int i = 0; i < 4; ++i) e.c.push_back(static_cast<uint8_t>((stage2_code_size >> (i * 8)) & 0xFF));
    if (enable_anti_debug) {
        e({0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00}); // mov rax, gs:[0x60]
        e({0x8B, 0x80, 0xBC, 0x00, 0x00, 0x00});                    // mov eax, [rax+0xBC]
        e({0x83, 0xE0, 0x70});                                     // and eax, 0x70
        e({0x34, stage2_key});                                     // xor al, stage2_key
    } else {
        e({0xB0, stage2_key});                                     // mov al, stage2_key
    }
    const size_t dec_loop = e.c.size();
    e({0x30, 0x07});                                // xor byte [rdi], al
    e({0xC0, 0xC0, s1_rol});                         // rol al, s1_rol
    e({0x04, s1_add});                              // add al, s1_add
    e({0x34, s1_xor});                              // xor al, s1_xor
    e({0x48, 0xFF, 0xC7});                          // inc rdi
    e({0xFF, 0xC9});                                // dec ecx
    e.back8(0x75, dec_loop);

    // call Stage 2
    e({0x48, 0xC7, 0x43, 0x28, 0x33, 0x00, 0x00, 0x00});         // mov qword [rbx+0x28], 0x33 (MARK: pre-call)
    e({0xE8, 0, 0, 0, 0});
    e.patch32(e.c.size() - 4, static_cast<int32_t>(kStage2Offset) -
                             static_cast<int32_t>(kStage1Offset + e.c.size()));

    // wipe Stage 2 code + tables + blobs
    e({0x48, 0x8D, 0xBB, 0x80, 0x0E, 0x00, 0x00});  // lea rdi, [rbx+kStage2Offset]
    e({0xB9});
    for (int i = 0; i < 4; ++i) e.c.push_back(static_cast<uint8_t>((wipe_len >> (i * 8)) & 0xFF));
    e({0x31, 0xC0});                                // xor eax, eax
    e({0xF3, 0xAA});                                // rep stosb

    const size_t s1_done = e.c.size();
    for (size_t pos : fix_s1_done) e.patch32(pos, static_cast<int32_t>(s1_done) - static_cast<int32_t>(pos + 4));

    e({0x48, 0x89, 0xEC});           // mov rsp, rbp
    e({0x5D});                       // pop rbp
    e({0x41, 0x5F});                 // pop r15
    e({0x41, 0x5E});                 // pop r14
    e({0x41, 0x5D});                 // pop r13
    e({0x41, 0x5C});                 // pop r12
    e({0x5F});                       // pop rdi
    e({0x5E});                       // pop rsi
    e({0x5B});                       // pop rbx
    e({0x41, 0x59});                 // pop r9
    e({0x41, 0x58});                 // pop r8
    e({0x5A});                       // pop rdx
    e({0x59});                       // pop rcx
    e({0xC3});                       // ret
    return e.c;
}

// ============================================================================
// Payload builder: header + decoys + bridge + EpStub + TlsStub + Stage 2 + tables
// + blobs + Stage 1.
// ============================================================================
std::vector<uint8_t> build_vpack_section_payload(
    const VPackHeader&               vhdr,
    uint64_t                         real_seed,
    const std::vector<VPackRegion>&  dyn_regions,
    const std::vector<uint32_t>&     dyn_relocs,
    const std::vector<uint8_t>&      blob_store,
    uint32_t                         vpack_sec_rva,
    bool                             enable_anti_debug,
    const std::vector<uint8_t>&      stolen_oep_bytes,
    uint64_t                         tls_cb_pair
) {
    std::vector<uint8_t> sec(kStage2Offset, 0);

    // noise fill for slack space
    uint64_t noise = real_seed ^ 0xF00DBAADBEEF1337ULL;
    for (size_t i = sizeof(VPackHeader); i < kStage2Offset; ++i) {
        noise = rotr64(noise, 11) + kGold64;
        sec[i] = static_cast<uint8_t>(noise & 0xFF);
    }

    std::memcpy(sec.data(), &vhdr, sizeof(VPackHeader));

    // Stage 1's one-shot gate reads word[hdr+0x06] (nonzero = "must unpack").
    // The header template keeps it 0, so write the REAL region count here — this is
    // just a public integer, the masked region TABLE itself stays only inside the
    // encrypted Stage 2 body (L11: no duplicate descriptor tables on disk).
    reinterpret_cast<VPackHeader*>(sec.data())->region_count =
        static_cast<uint16_t>(dyn_regions.size() != 0 ? dyn_regions.size() : 1);

    // Decoy import area (L5): descriptor-shaped noise, never parseable (leading zeros)
    {
        uint64_t decoy = crypto::poly_permute_64(real_seed ^ vpack_sec_rva, 0xD3C0A5A71B4F9E2ULL);
        for (size_t i = kDecoyImportOffset; i < kDecoyImportOffset + 0xC0; ++i) {
            decoy = rotr64(decoy, 13) + kM2;
            sec[i] = static_cast<uint8_t>((decoy ^ (decoy >> 29)) & 0xFF);
        }
        std::memset(sec.data() + kDecoyImportOffset, 0, sizeof(IMAGE_IMPORT_DESCRIPTOR) * 2);
    }

    // Stolen-OEP bridge (L8): [stolen prologue bytes][E9 rel32 -> OEP+stolen_n][junk]
    {
        std::vector<uint8_t> bridge(kStolenOepSpan, 0);
        const size_t stolen_n = (stolen_oep_bytes.size() >= 5) ? stolen_oep_bytes.size() - 5 : 0;
        const size_t n = (stolen_oep_bytes.size() < stolen_n) ? stolen_oep_bytes.size() : stolen_n;
        std::memcpy(bridge.data(), stolen_oep_bytes.data(), n);
        if (stolen_oep_bytes.size() >= stolen_n + 5) {
            std::memcpy(bridge.data() + stolen_n, stolen_oep_bytes.data() + stolen_n, 5);
        }
        uint64_t junk = crypto::poly_permute_64(real_seed ^ 0xC0DEC0DEC0DEC0DEULL, 0x517CC1B727220A95ULL);
        for (size_t i = stolen_n + 5; i < kStolenOepSpan; ++i) {
            junk = rotr64(junk, 11) + kGold64;
            uint8_t b = static_cast<uint8_t>((junk ^ (junk >> 29)) & 0xFF);
            bridge[i] = (b == 0xCC || b == 0x00) ? static_cast<uint8_t>(b ^ 0x48) : b;
        }

        // Mask the bridge with the chained cipher (runtime seed = real_seed ^ salt ^ poison)
        uint64_t s = real_seed ^ kBridgeSalt;
        for (size_t i = 0; i < kStolenOepSpan; ++i) {
            const uint8_t ks    = chained_ks_step(s);
            const uint8_t plain = bridge[i];
            sec[kStolenOepOffset + i] = static_cast<uint8_t>(plain ^ ks);
            chained_feed_plain(s, plain);
        }
    }

    // ---------------- EpStub ----------------
    {
        std::vector<uint8_t> ep;
        auto emit = [&](std::initializer_list<uint8_t> b) { ep.insert(ep.end(), b.begin(), b.end()); };
        auto w32 = [&](size_t pos, int32_t v) {
            for (int i = 0; i < 4; ++i) ep[pos + i] = static_cast<uint8_t>((v >> (i * 8)) & 0xFF);
        };

        emit({0x50, 0x31, 0xC0, 0x74, 0x01, 0xE9, 0x58});          // opaque predicate (jz +1 skips the E9 junk; pop rax restores)
        emit({0xE8, 0, 0, 0, 0});                                  // call Stage 1
        w32(ep.size() - 4, static_cast<int32_t>(kStage1Offset) - static_cast<int32_t>(kEpStubOffset + ep.size()));
        emit({0x65, 0x4C, 0x8B, 0x1C, 0x25, 0x60, 0x00, 0x00, 0x00}); // mov r11, gs:[0x60]
        emit({0x4D, 0x8B, 0x5B, 0x10});                            // mov r11, [r11+0x10] (ImageBase)

        // -------- TLS replay: run the ORIGINAL callbacks NOW (full unpack done, IAT live) --------
        emit({0x4C, 0x89, 0xD9});                                  // mov rcx, r11 (DllHandle = ImageBase)
        emit({0xBA, 0x01, 0x00, 0x00, 0x00});                      // mov edx, 1 (DLL_PROCESS_ATTACH)
        emit({0x45, 0x31, 0xC0});                                  // xor r8d, r8d (Reserved = 0)
        emit({0x48, 0x8D, 0x05, 0, 0, 0, 0});                      // lea rax, [hdr]
        w32(ep.size() - 4, -static_cast<int32_t>(kEpStubOffset + ep.size()));
        emit({0x8B, 0x80, 0xE0, 0x08, 0x00, 0x00});                // mov eax, [rax+0x8E0] (cb0 dword)
        emit({0x85, 0xC0});                                        // test eax, eax
        const size_t jz_cb0 = ep.size() + 1; emit({0x74, 0x00});   // jz skip_cb0
        emit({0x4C, 0x01, 0xD8});                                  // add rax, r11 (callback VA)
        emit({0xFF, 0xD0});                                        // call rax
        {
            const size_t skip_cb0 = ep.size();
            ep[jz_cb0] = static_cast<uint8_t>(skip_cb0 - (jz_cb0 + 1));
        }
        // second callback (high dword of the pair at +0x8E4, NOT +0x8E8)
        emit({0x48, 0x8D, 0x05, 0, 0, 0, 0});                      // lea rax, [hdr]
        w32(ep.size() - 4, -static_cast<int32_t>(kEpStubOffset + ep.size()));
        emit({0x8B, 0x80, 0xE4, 0x08, 0x00, 0x00});                // mov eax, [rax+0x8E4] (cb1 dword)
        emit({0x85, 0xC0});                                        // test eax, eax
        const size_t jz_cb1 = ep.size() + 1; emit({0x74, 0x00});   // jz skip_cb1
        emit({0x4C, 0x01, 0xD8});                                  // add rax, r11
        emit({0xFF, 0xD0});                                        // call rax
        {
            const size_t skip_cb1 = ep.size();
            ep[jz_cb1] = static_cast<uint8_t>(skip_cb1 - (jz_cb1 + 1));
        }

        // -------- handoff to the stolen-OEP bridge --------
        emit({0x48, 0x8D, 0x05, 0, 0, 0, 0});                      // lea rax, [hdr]
        w32(ep.size() - 4, -static_cast<int32_t>(kEpStubOffset + ep.size()));
        emit({0x44, 0x8B, 0x50, 0x0C});                            // mov r10d, [rax+0x0C]
        emit({0x44, 0x33, 0x50, 0x10});                            // xor r10d, [rax+0x10] (bridge_rva)
        emit({0x48, 0xC7, 0x40, 0x08, 0x00, 0x00, 0x00, 0x00});    // mov qword [rax+0x08], 0
        emit({0xC7, 0x40, 0x10, 0x00, 0x00, 0x00, 0x00});          // mov dword [rax+0x10], 0 (keep slot intact!)
        emit({0x4B, 0x8D, 0x0C, 0x13});                            // lea rcx, [r11+r10]
        emit({0xFF, 0xE1});                                        // jmp rcx (bridge)
        std::memcpy(sec.data() + kEpStubOffset, ep.data(), ep.size());
    }

    // ---------------- TlsStub ----------------
    // The TLS array slots were zeroed at pack time, so the loader never dispatches
    // into the stub from TLS anymore; the original callbacks are replayed by EpStub.
    // This stub remains only as a safety net (a plain RET) in case anything still
    // points here, and it keeps the CRC-gate window structurally unchanged.
    {
        std::vector<uint8_t> tls;
        auto emit = [&](std::initializer_list<uint8_t> b) { tls.insert(tls.end(), b.begin(), b.end()); };
        emit({0x31, 0xC0, 0x74, 0x01, 0xE9});                      // opaque predicate (jz +1 skips the E9 junk)
        emit({0xC3});                                              // ret
        std::memcpy(sec.data() + kTlsStubOffset, tls.data(), tls.size());
    }

    // ---------------- Stage 2 (code + appended tables) ----------------
    const uint64_t secret_share = derive_secret_stub_share(real_seed);
    const uint64_t morph_key    = derive_morph_key(real_seed);
    const uint32_t bridge_rva   = vpack_sec_rva + kStolenOepOffset;

    Stage2Out s2 = emit_stage2(secret_share, dyn_regions.size(), dyn_relocs.size(),
                              bridge_rva, tls_cb_pair, enable_anti_debug);
    std::vector<uint8_t>& stage2 = s2.code;
    const size_t stage2_code_size = stage2.size();

    // Append masked region table + reloc table into the Stage 2 vector
    const size_t off_regions = stage2.size();
    {
        const auto* reg_bytes = reinterpret_cast<const uint8_t*>(dyn_regions.data());
        stage2.insert(stage2.end(), reg_bytes, reg_bytes + dyn_regions.size() * sizeof(VPackRegion));
    }
    const size_t off_relocs = stage2.size();
    {
        const auto* rel_bytes = reinterpret_cast<const uint8_t*>(dyn_relocs.data());
        stage2.insert(stage2.end(), rel_bytes, rel_bytes + dyn_relocs.size() * sizeof(uint32_t));
    }

    // Patch rip-lea fixups (target offsets are within the Stage 2 vector)
    {
        int32_t disp = static_cast<int32_t>(off_regions) - static_cast<int32_t>(s2.fix_regions_table + 4);
        for (int i = 0; i < 4; ++i) stage2[s2.fix_regions_table + i] = static_cast<uint8_t>((disp >> (i * 8)) & 0xFF);
    }
    {
        int32_t disp = static_cast<int32_t>(off_relocs) - static_cast<int32_t>(s2.fix_relocs_table + 4);
        for (int i = 0; i < 4; ++i) stage2[s2.fix_relocs_table + i] = static_cast<uint8_t>((disp >> (i * 8)) & 0xFF);
    }
    {
        // Blob store begins right after the relocation table inside the Stage 2 vector
        const size_t off_blobs = off_relocs + dyn_relocs.size() * sizeof(uint32_t);
        int32_t disp = static_cast<int32_t>(off_blobs) - static_cast<int32_t>(s2.fix_blobs_table + 4);
        for (int i = 0; i < 4; ++i) stage2[s2.fix_blobs_table + i] = static_cast<uint8_t>((disp >> (i * 8)) & 0xFF);
    }

    // Metamorphic streaming cipher for Stage 2 code (per-build parameters)
    const uint8_t stage2_key = static_cast<uint8_t>(((real_seed >> 19) & 0xFFu) | 0x05u);
    const uint8_t s1_rol     = static_cast<uint8_t>(((morph_key >> 7) & 0x06u) | 0x01u);
    const uint8_t s1_add     = static_cast<uint8_t>(((morph_key >> 15) & 0xFEu) | 0x01u);
    const uint8_t s1_xor     = static_cast<uint8_t>(((morph_key >> 23) & 0xFFu) | 0x11u);
    {
        uint8_t k = stage2_key;
        for (size_t i = 0; i < stage2_code_size; ++i) {
            stage2[i] ^= k;
            k = static_cast<uint8_t>((k << s1_rol) | (k >> (8 - s1_rol)));
            k = static_cast<uint8_t>(k + s1_add);
            k ^= s1_xor;
        }
    }

    // ---------------- Stage 1 ----------------
    const uint32_t wipe_len = static_cast<uint32_t>(stage2.size() + blob_store.size());
    const uint32_t stub_crc = crc32_ieee(sec.data() + kEpStubOffset, kStage1Offset - kEpStubOffset);
    std::vector<uint8_t> s1 = emit_stage1(
        static_cast<uint32_t>(stage2_code_size), wipe_len,
        stage2_key, s1_rol, s1_add, s1_xor, stub_crc, enable_anti_debug
    );

    // Assemble the section
    sec.resize(kStage2Offset + stage2.size() + blob_store.size());
    std::memcpy(sec.data() + kStage1Offset, s1.data(), s1.size());
    std::memcpy(sec.data() + kStage2Offset, stage2.data(), stage2.size());
    std::memcpy(sec.data() + kStage2Offset + stage2.size(), blob_store.data(), blob_store.size());
    return sec;
}

bool is_debug_or_symbol_section(const IMAGE_SECTION_HEADER& sec) noexcept {
    char name[9]{};
    std::memcpy(name, sec.Name, 8);
    // MinGW DWARF sections use "/4", "/14", "/29" string-table aliases.
    // CAUTION: "/N" with a SMALL number is often the RUNTIME-critical .eh_frame —
    // never strip such sections; only strip explicit ".debug*" DWARF payloads.
    if (std::strncmp(name, ".debug", 6) == 0) {
        return true;
    }
    if (name[0] == '/') {
        // String-table alias: resolve the real name via the COFF string table when possible.
        // Without the table we conservatively KEEP the section (stripping .eh_frame breaks
        // the PE loader on MinGW builds and destroys SEH unwinding).
        return false;
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
        if (err) *err = "Failed while writing output file";
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
    if (!valid_pe64_) return false;
    for (const auto& sec : list_sections()) {
        if (sec.raw_offset + sizeof(VPackHeader) > data_.size()) {
            continue;
        }
        const auto* hdr = reinterpret_cast<const VPackHeader*>(data_.data() + sec.raw_offset);
        const uint32_t exp_magic = compute_disk_header_magic(hdr->master_seed);
        const uint32_t exp_ver   = compute_disk_header_ver(hdr->master_seed);
        if (hdr->magic != exp_magic || hdr->version != exp_ver) {
            continue;
        }
        if (out_header) {
            *out_header = *hdr;

            // Recover real_seed via the Stage 1 cipher params + secret_share prologue,
            // then decrypt the stolen-OEP bridge and read the original OEP from its jmp.
            uint32_t orig_ep_rva = 0;
            if (sec.raw_offset + kStage2Offset + 80 <= data_.size()) {
                const uint8_t* s1 = data_.data() + sec.raw_offset + kStage1Offset;
                uint8_t s2_key = 0, s1_rol = 0, s1_add = 0, s1_xor = 0;
                bool found_s1_params = false;
                for (size_t i = 30; i + 16 < (kStage2Offset - kStage1Offset); ++i) {
                    if (s1[i] == 0x30 && s1[i + 1] == 0x07 &&
                        s1[i + 2] == 0xC0 && s1[i + 3] == 0xC0 &&
                        s1[i + 5] == 0x04 && s1[i + 7] == 0x34) {
                        s2_key = s1[i - 1];
                        s1_rol = s1[i + 4];
                        s1_add = s1[i + 6];
                        s1_xor = s1[i + 8];
                        found_s1_params = true;
                        break;
                    }
                }
                if (found_s1_params) {
                    uint8_t s2_head[80]{};
                    uint8_t k = s2_key;
                    const uint8_t* s2_enc = data_.data() + sec.raw_offset + kStage2Offset;
                    for (size_t i = 0; i < sizeof(s2_head); ++i) {
                        s2_head[i] = static_cast<uint8_t>(s2_enc[i] ^ k);
                        k = static_cast<uint8_t>((k << s1_rol) | (k >> (8 - s1_rol)));
                        k = static_cast<uint8_t>(k + s1_add);
                        k ^= s1_xor;
                    }
                    for (size_t i = 0; i + 13 <= sizeof(s2_head); ++i) {
                        if (s2_head[i] == 0x49 && s2_head[i + 1] == 0xBB &&
                            s2_head[i + 10] == 0x4D && s2_head[i + 11] == 0x31 && s2_head[i + 12] == 0xCB) {
                            uint64_t secret_share = 0;
                            std::memcpy(&secret_share, s2_head + i + 2, sizeof(uint64_t));
                            const uint64_t real_seed = hdr->master_seed ^ secret_share;

                            if (sec.raw_offset + kStolenOepOffset + kStolenOepSpan <= data_.size()) {
                                uint8_t bridge[kStolenOepSpan]{};
                                std::memcpy(bridge, data_.data() + sec.raw_offset + kStolenOepOffset, kStolenOepSpan);
                                uint64_t s = real_seed ^ kBridgeSalt;
                                for (size_t b = 0; b < kStolenOepSpan; ++b) {
                                    const uint8_t ks = chained_ks_step(s);
                                    const uint8_t plain = static_cast<uint8_t>(bridge[b] ^ ks);
                                    bridge[b] = plain;
                                    chained_feed_plain(s, plain);
                                }
                                // Scan for the E9 forwarder at an instruction boundary
                                const uint32_t bridge_rva = sec.virtual_address + kStolenOepOffset;
                                for (size_t pos = 4; pos + 5 <= kStolenOepSpan; ++pos) {
                                    if (bridge[pos] == 0xE9) {
                                        int32_t rel = static_cast<int32_t>(
                                            static_cast<uint32_t>(bridge[pos + 1]) |
                                            (static_cast<uint32_t>(bridge[pos + 2]) << 8) |
                                            (static_cast<uint32_t>(bridge[pos + 3]) << 16) |
                                            (static_cast<uint32_t>(bridge[pos + 4]) << 24));
                                        const uint32_t cont_rva = bridge_rva + static_cast<uint32_t>(pos) + 5 +
                                                                  static_cast<uint32_t>(rel);
                                        orig_ep_rva = cont_rva - static_cast<uint32_t>(pos);
                                        break;
                                    }
                                }
                            }
                            break;
                        }
                    }
                }
            }
            out_header->original_entry_rva = orig_ep_rva;
        }
        return true;
    }
    return false;
}

PackResult PeImage::pack(const PackOptions& opts) {
    PackResult res{};
    if (!valid_pe64_) {
        res.message = "Invalid PE64 image";
        return res;
    }

    if (is_already_packed()) {
        res.message = "Binary is already packed with the VPack stub";
        return res;
    }

    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(data_.data() + nt_headers_offset_);
    IMAGE_SECTION_HEADER* first_sec = IMAGE_FIRST_SECTION(nt);
    uint16_t num_sec = nt->FileHeader.NumberOfSections;

    // 1. Strip symbols & debug sections (unchanged)
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

    const uint32_t new_sec_hdr_end = static_cast<uint32_t>(
        reinterpret_cast<const uint8_t*>(&first_sec[num_sec + 1]) - data_.data()
    );
    if (new_sec_hdr_end > nt->OptionalHeader.SizeOfHeaders) {
        res.message = "Not enough space in PE header to append the stub section header";
        return res;
    }

    // 2. Derive per-build seed & keys
    uint64_t seed = opts.custom_seed;
    if (seed == 0) {
        auto now = static_cast<uint64_t>(
            std::chrono::high_resolution_clock::now().time_since_epoch().count()
        );
        seed = crypto::fnv1a_64(data_.data(), data_.size()) ^ now ^ 0xA983C1E59F27B4D3ULL;
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
    const uint32_t bridge_rva = new_sec_va + kStolenOepOffset;

    const uint64_t secret_share = derive_secret_stub_share(seed);
    const uint64_t public_salt  = seed ^ secret_share;
    const uint64_t morph_key    = derive_morph_key(seed);
    const uint32_t m1           = derive_header_field_mask(seed, kIdRegionM1);
    const uint32_t m2           = derive_header_field_mask(seed, kIdRegionM2);
    const uint64_t keymask64    = static_cast<uint64_t>(derive_header_field_mask(seed, kIdKeyMaskLo)) |
                                  (static_cast<uint64_t>(derive_header_field_mask(seed, kIdKeyMaskHi)) << 32);
    const uint32_t orig_ep_plain = nt->OptionalHeader.AddressOfEntryPoint;

    // 3. Force ASLR + NX (L9)
    nt->OptionalHeader.DllCharacteristics |= IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE |
                                             IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA |
                                             IMAGE_DLLCHARACTERISTICS_NX_COMPAT;

    // 4. Stolen-OEP capture + forwarder (L8) — must run before any .text mutation.
    //    The stolen span ENDS at the first near-call (E8 rel32) inside the entry
    //    prologue, so the bridge always resumes on a REAL instruction boundary
    //    (a fixed 24-byte cut lands mid-instruction on MinGW CRTs -> garbage opcodes!).
    uint32_t stolen_n = 0;
    {
        uint32_t oep_off = 0;
        if (rva_to_file_offset(orig_ep_plain, oep_off) && oep_off + 64 <= data_.size()) {
            const uint8_t* ep_bytes = data_.data() + oep_off;
            for (uint32_t i = 0; i + 5 < 64; ++i) {
                if (ep_bytes[i] == 0xE8) {
                    const int32_t rel = static_cast<int32_t>(
                        static_cast<uint32_t>(ep_bytes[i + 1]) |
                        (static_cast<uint32_t>(ep_bytes[i + 2]) << 8) |
                        (static_cast<uint32_t>(ep_bytes[i + 3]) << 16) |
                        (static_cast<uint32_t>(ep_bytes[i + 4]) << 24));
                    const uint32_t target = orig_ep_plain + i + 5 + static_cast<uint32_t>(rel);
                    uint32_t txt_va = 0, txt_sz = 0;
                    bool in_text = false;
                    for (WORD s_i = 0; s_i < num_sec; ++s_i) {
                        if (first_sec[s_i].Characteristics & IMAGE_SCN_CNT_CODE) {
                            txt_va = first_sec[s_i].VirtualAddress;
                            txt_sz = first_sec[s_i].Misc.VirtualSize ? first_sec[s_i].Misc.VirtualSize
                                                                    : first_sec[s_i].SizeOfRawData;
                            if (target >= txt_va && target < txt_va + txt_sz) { in_text = true; break; }
                        }
                    }
                    if (in_text && i >= 5) { // steal at least the push/sub prologue
                        stolen_n = i;
                        break;
                    }
                }
            }
        }
    }
    if (stolen_n == 0) stolen_n = 24; // fallback (may cut mid-insn on exotic CRTs)

    std::vector<uint8_t> stolen(stolen_n + 5, 0);
    {
        uint32_t oep_off = 0;
        if (rva_to_file_offset(orig_ep_plain, oep_off) && oep_off + stolen_n + 29 <= data_.size()) {
            std::memcpy(stolen.data(), data_.data() + oep_off, stolen_n);
            // jmp rel32 at bridge end -> real OEP continuation (OEP + stolen_n)
            const int32_t rel = static_cast<int32_t>(orig_ep_plain + stolen_n) -
                               static_cast<int32_t>(bridge_rva + stolen_n + 5);
            stolen[stolen_n] = 0xE9;
            for (int i = 0; i < 4; ++i) {
                stolen[stolen_n + 1 + i] = static_cast<uint8_t>((rel >> (i * 8)) & 0xFF);
            }
            // Overwrite the on-disk OEP with a 5-byte E9 forwarder trap into the bridge.
            // CRITICAL: the junk fill covers ONLY [5, stolen_n) — the original instruction at
            // OEP+stolen_n (e.g. `call __tmainCRTStartup`) MUST SURVIVE because the bridge's
            // own E9 lands there at runtime after executing the stolen prologue!
            uint8_t* oep_disk = data_.data() + oep_off;
            const int32_t fwd = static_cast<int32_t>(bridge_rva) - static_cast<int32_t>(orig_ep_plain + 5);
            oep_disk[0] = 0xE9;
            for (int i = 0; i < 4; ++i) {
                oep_disk[1 + i] = static_cast<uint8_t>((fwd >> (i * 8)) & 0xFF);
            }
            uint64_t junk = crypto::poly_permute_64(seed ^ orig_ep_plain, morph_key);
            for (size_t i = 5; i < stolen_n; ++i) {
                junk = rotr64(junk, 11) + kGold64;
                uint8_t b = static_cast<uint8_t>((junk ^ (junk >> 29)) & 0xFF);
                oep_disk[i] = (b == 0xCC || b == 0x00) ? static_cast<uint8_t>(b ^ 0x48) : b;
            }
        }
    }

    // 5. Masked VPackHeader (zero duplicate descriptor tables — L11)
    VPackHeader vhdr{};
    vhdr.magic                  = compute_disk_header_magic(public_salt);
    vhdr.version                = compute_disk_header_ver(public_salt);
    vhdr.region_count           = 0;
    vhdr.flags                  = opts.protection_flags ^ derive_header_field_mask(seed, kIdFlags);
    vhdr.original_entry_rva     = derive_header_field_mask(seed, kIdImportRva); // noise
    vhdr.master_seed            = public_salt;
    vhdr.preferred_image_base   = nt->OptionalHeader.ImageBase;
    vhdr.orig_tls_callback_rva  = 0 ^ derive_header_field_mask(seed, kIdTlsCb);
    vhdr.code_reloc_count       = 0 ^ derive_header_field_mask(seed, kIdImportRva); // import desc rva (masked)
    vhdr.orig_pdata_rva         = 0 ^ derive_header_field_mask(seed, kIdPdataRva);
    vhdr.orig_pdata_size        = 0 ^ derive_header_field_mask(seed, kIdPdataSize);
    vhdr.orig_import_rva        = 0;  // runtime live-key slot
    vhdr.vcode_rva              = 0 ^ derive_header_field_mask(seed, kIdVcodeRva);
    vhdr.vcode_size             = 0 ^ derive_header_field_mask(seed, kIdVcodeSize);
    vhdr.vinit_rva              = 0 ^ derive_header_field_mask(seed, kIdVinitRva);
    vhdr.vinit_size             = 0 ^ derive_header_field_mask(seed, kIdVinitSize);

    for (WORD i = 0; i < num_sec; ++i) {
        char sname[9]{};
        std::memcpy(sname, first_sec[i].Name, 8);
        uint32_t sec_sz = first_sec[i].Misc.VirtualSize;
        if (sec_sz == 0 || sec_sz > first_sec[i].SizeOfRawData) {
            sec_sz = first_sec[i].SizeOfRawData;
        }
        if (std::strcmp(sname, ".vcode") == 0) {
            vhdr.vcode_rva  = first_sec[i].VirtualAddress ^ derive_header_field_mask(seed, kIdVcodeRva);
            vhdr.vcode_size = sec_sz ^ derive_header_field_mask(seed, kIdVcodeSize);
        } else if (std::strcmp(sname, ".vinit") == 0) {
            vhdr.vinit_rva  = first_sec[i].VirtualAddress ^ derive_header_field_mask(seed, kIdVinitRva);
            vhdr.vinit_size = sec_sz ^ derive_header_field_mask(seed, kIdVinitSize);
        }
    }

    // 6. Neutralize the TLS callback array: record the ORIGINAL callback RVAs for
    //    EpStub's post-unpack replay, then ZERO every slot so the loader runs NO
    //    callback while the image is still encrypted (running our stub inside a
    //    loader TLS callback proved fatal across CRTs — ntdll __report_gsfailure).
    uint32_t tls_cb0 = 0, tls_cb1 = 0;
    const auto& tls_dir_entry = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (tls_dir_entry.VirtualAddress != 0 && tls_dir_entry.Size >= sizeof(IMAGE_TLS_DIRECTORY64)) {
        uint32_t tls_off = 0;
        if (rva_to_file_offset(tls_dir_entry.VirtualAddress, tls_off) &&
            tls_off + sizeof(IMAGE_TLS_DIRECTORY64) <= data_.size()) {
            const auto* tls_dir = reinterpret_cast<const IMAGE_TLS_DIRECTORY64*>(data_.data() + tls_off);
            if (tls_dir->AddressOfCallBacks > nt->OptionalHeader.ImageBase) {
                uint32_t cb_array_rva = static_cast<uint32_t>(tls_dir->AddressOfCallBacks - nt->OptionalHeader.ImageBase);
                uint32_t cb_off = 0;
                if (rva_to_file_offset(cb_array_rva, cb_off) && cb_off + sizeof(uint64_t) * 4 <= data_.size()) {
                    auto* cb_slot = reinterpret_cast<uint64_t*>(data_.data() + cb_off);
                    for (int slot_i = 0; slot_i < 4; ++slot_i) {
                        if (cb_slot[slot_i] > nt->OptionalHeader.ImageBase) {
                            const uint32_t cb_rva = static_cast<uint32_t>(cb_slot[slot_i] - nt->OptionalHeader.ImageBase);
                            if (tls_cb0 == 0)      tls_cb0 = cb_rva;
                            else if (tls_cb1 == 0) tls_cb1 = cb_rva;
                        }
                        cb_slot[slot_i] = 0ULL;
                    }

                    // CRITICAL: also neutralize every DIR64 relocation that targets the
                    // callback array — otherwise the loader re-populates the zeroed
                    // slots with (0 + ASLR delta) garbage and calls it as a callback!
                    {
                        auto& rel_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
                        if (rel_dir.VirtualAddress != 0 && rel_dir.Size > 0) {
                            uint32_t rel_off2 = 0;
                            if (rva_to_file_offset(rel_dir.VirtualAddress, rel_off2)) {
                                uint32_t parsed2 = 0;
                                while (parsed2 + sizeof(IMAGE_BASE_RELOCATION) <= rel_dir.Size &&
                                       rel_off2 + parsed2 + sizeof(IMAGE_BASE_RELOCATION) <= data_.size()) {
                                    auto* blk = reinterpret_cast<IMAGE_BASE_RELOCATION*>(data_.data() + rel_off2 + parsed2);
                                    if (blk->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) break;
                                    uint32_t cnt = (blk->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
                                    auto* ents = reinterpret_cast<uint16_t*>(blk + 1);
                                    for (uint32_t k = 0; k < cnt; ++k) {
                                        uint16_t type = ents[k] >> 12;
                                        uint16_t off  = ents[k] & 0x0FFF;
                                        uint32_t rva2 = blk->VirtualAddress + off;
                                        if (type == IMAGE_REL_BASED_DIR64 &&
                                            rva2 >= cb_array_rva &&
                                            rva2 < cb_array_rva + sizeof(uint64_t) * 4) {
                                            ents[k] = 0; // ABSOLUTE no-op for the loader; NOT deferred
                                        }
                                    }
                                    parsed2 += blk->SizeOfBlock;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    const uint64_t tls_cb_pair =
        (opts.inject_entry_stub ? 1u : 0u) *
        (static_cast<uint64_t>(tls_cb0) | (static_cast<uint64_t>(tls_cb1) << 32));

    std::vector<VPackRegion> dyn_regions;
    std::vector<uint32_t>    dyn_relocs;
    std::vector<uint8_t>     blob_store;
    uint32_t                 blob_cursor = 0;

    // 7. Gap-sled entanglement (unchanged, runs before encryption)
    {
        const auto& exc_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        uint32_t pdata_off = 0;
        if (exc_dir.VirtualAddress != 0 &&
            exc_dir.Size >= sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY) &&
            rva_to_file_offset(exc_dir.VirtualAddress, pdata_off) &&
            pdata_off + exc_dir.Size <= data_.size()) {
            const size_t entry_count = exc_dir.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
            const auto*  entries     = reinterpret_cast<const IMAGE_RUNTIME_FUNCTION_ENTRY*>(data_.data() + pdata_off);
            uint64_t     bogus_prng  = seed ^ 0xE791C3A58B2D4F19ULL;

            for (size_t idx = 0; idx + 1 < entry_count; ++idx) {
                const uint32_t gap_start = entries[idx].EndAddress;
                const uint32_t gap_end   = entries[idx + 1].BeginAddress;
                if (gap_end > gap_start && (gap_end - gap_start) <= 32) {
                    uint32_t gap_file_off = 0;
                    if (rva_to_file_offset(gap_start, gap_file_off) &&
                        gap_file_off + (gap_end - gap_start) <= data_.size()) {
                        uint8_t* gap_ptr = data_.data() + gap_file_off;
                        const uint32_t gap_len = gap_end - gap_start;
                        bool all_pad = true;
                        for (uint32_t b = 0; b < gap_len; ++b) {
                            if (gap_ptr[b] != 0x90 && gap_ptr[b] != 0xCC) {
                                all_pad = false;
                                break;
                            }
                        }
                        if (all_pad) {
                            for (uint32_t b = 0; b < gap_len; ++b) {
                                bogus_prng = rotr64(bogus_prng, 11) + kGold64;
                                uint8_t rbyte = static_cast<uint8_t>((bogus_prng ^ (bogus_prng >> 29)) & 0xFFu);
                                if (rbyte == 0x90 || rbyte == 0x00 || rbyte == 0xCC) {
                                    rbyte ^= 0x48u;
                                }
                                gap_ptr[b] = rbyte;
                            }
                        }
                    }
                }
            }
        }
    }

    // 8. AOT x64->VM lifter & on-disk shredder (unchanged)
    {
        const uint64_t img_base = nt->OptionalHeader.ImageBase;
        for (WORD i = 0; i < num_sec; ++i) {
            char sname[9]{};
            std::memcpy(sname, first_sec[i].Name, 8);
            if (std::strcmp(sname, ".data") != 0) continue;

            const uint32_t sec_raw  = first_sec[i].PointerToRawData;
            const uint32_t sec_size = first_sec[i].SizeOfRawData;
            if (sec_raw + sec_size > data_.size() || sec_size < sizeof(virtualizer::AotVirtualSlotRaw)) {
                break;
            }

            uint16_t used_aot_slots = 0;

            for (uint32_t off = 0; off + sizeof(virtualizer::AotVirtualSlotRaw) <= sec_size; off += 8) {
                auto* slot = reinterpret_cast<virtualizer::AotVirtualSlotRaw*>(data_.data() + sec_raw + off);
                if (slot->magic != virtualizer::kAotSlotMagic || slot->pre_lifted != 0) {
                    continue;
                }
                if (slot->target_fn_va <= img_base || slot->thunk_fn_va <= img_base) {
                    continue;
                }

                uint16_t sid = slot->slot_id;
                if (sid >= virtualizer::kMaxVirtualizedSlots || (used_aot_slots & (1u << sid)) != 0) {
                    uint16_t new_sid = 0xFFFFu;
                    for (uint16_t cand = 0; cand < virtualizer::kMaxVirtualizedSlots; ++cand) {
                        if ((used_aot_slots & (1u << cand)) == 0) {
                            new_sid = cand;
                            break;
                        }
                    }
                    if (new_sid == 0xFFFFu) continue;

                    const uint16_t old_sid = (sid < virtualizer::kMaxVirtualizedSlots) ? sid : 0;
                    bool found_thunk = false;
                    for (size_t pos = 0; pos + virtualizer::kMaxVirtualizedSlots * sizeof(uint64_t) <= data_.size(); pos += 8) {
                        const auto* tbl = reinterpret_cast<const uint64_t*>(data_.data() + pos);
                        if (tbl[old_sid] == slot->thunk_fn_va &&
                            tbl[new_sid] > img_base &&
                            tbl[new_sid] < img_base + nt->OptionalHeader.SizeOfImage) {
                            slot->thunk_fn_va = tbl[new_sid];
                            slot->slot_id     = new_sid;
                            sid               = new_sid;
                            found_thunk       = true;
                            break;
                        }
                    }
                    if (!found_thunk) continue;
                }

                const uint32_t target_rva = static_cast<uint32_t>(slot->target_fn_va - img_base);
                const uint32_t thunk_rva  = static_cast<uint32_t>(slot->thunk_fn_va - img_base);
                uint32_t target_file_off  = 0;
                if (!rva_to_file_offset(target_rva, target_file_off) || target_file_off + 16 > data_.size()) {
                    continue;
                }

                const size_t max_scan = (data_.size() - target_file_off < 2048)
                    ? (data_.size() - target_file_off)
                    : 2048;

                vm::VmProgram prog{};
                size_t native_size   = 0;
                size_t decoded_insns = 0;
                const uint64_t aot_seed = crypto::poly_permute_64(seed ^ target_rva, 0x9F81E3A5C72B4D19ULL);

                if (virtualizer::lift_x64_function(
                        data_.data() + target_file_off,
                        max_scan,
                        aot_seed,
                        prog,
                        &native_size,
                        &decoded_insns,
                        target_rva) &&
                    native_size >= 7 &&
                    prog.bytecode.size() <= sizeof(slot->bytecode)) {

                    used_aot_slots |= static_cast<uint16_t>(1u << sid);
                    slot->magic            = aot_seed ^ 0xA5A55A5A9E3779B9ULL;
                    slot->pre_lifted       = 1;
                    slot->bytecode_size    = static_cast<uint32_t>(prog.bytecode.size());
                    slot->vm_seed          = prog.seed;
                    slot->integrity_tag    = prog.integrity_tag;
                    slot->native_code_size = static_cast<uint32_t>(native_size);
                    slot->decoded_insns    = static_cast<uint32_t>(decoded_insns);

                    for (size_t b = 0; b < prog.bytecode.size(); ++b) {
                        const uint8_t mask = crypto::poly_stream_byte(prog.seed, b);
                        slot->bytecode[b]  = static_cast<uint8_t>(prog.bytecode[b] ^ mask);
                    }

                    uint8_t* fn_disk = data_.data() + target_file_off;
                    const int32_t rel_jmp = static_cast<int32_t>(thunk_rva) - static_cast<int32_t>(target_rva + 5);
                    fn_disk[0] = 0xE9;
                    for (int b = 0; b < 4; ++b) {
                        fn_disk[1 + b] = static_cast<uint8_t>((rel_jmp >> (b * 8)) & 0xFFu);
                    }
                    fn_disk[5] = 0x0F;
                    fn_disk[6] = 0x0B;

                    uint64_t noise2 = aot_seed ^ 0xD8B39A17E4C28F95ULL;
                    for (size_t b = 7; b < native_size; ++b) {
                        noise2 = crypto::poly_permute_64(noise2, b ^ kGold64);
                        fn_disk[b] = static_cast<uint8_t>((noise2 ^ (noise2 >> 23)) & 0xFFu);
                    }
                }
            }
            break;
        }
    }

    // 9. Compress + chain-cipher region encryption (L1/L6)
    auto encrypt_section_range = [&](WORD sec_idx, uint32_t range_rva, uint32_t range_size, uint64_t key_salt) {
        if (range_size == 0) return;
        uint32_t sec_va  = first_sec[sec_idx].VirtualAddress;
        uint32_t sec_raw = first_sec[sec_idx].PointerToRawData;
        if (range_rva < sec_va) return;
        uint32_t offset_in_sec = range_rva - sec_va;
        if (offset_in_sec + range_size > first_sec[sec_idx].SizeOfRawData) return;
        if (sec_raw + offset_in_sec + range_size > data_.size()) return;

        // Defer DIR64 relocs inside this range (masked with the reloc field mask)
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
                            // Skip relocs inside the stolen OEP window (already relocated-safe)
                            const bool in_stolen = (orig_ep_plain != 0) &&
                                (rva >= orig_ep_plain) && (rva < orig_ep_plain + stolen_n);
                            if (!in_stolen) {
                                dyn_relocs.push_back(rva ^ derive_header_field_mask(seed, kIdRelocMask));
                            }
                            entries[k] = 0;
                        }
                    }
                    parsed += blk->SizeOfBlock;
                }
            }
        }

        // LZSS compress the plaintext range
        const uint8_t* plain = data_.data() + sec_raw + offset_in_sec;
        std::vector<uint8_t> blob = lzss_compress(plain, range_size, seed ^ key_salt ^ 0x9E3779B9ULL);

        // Chain-cipher the blob with the region key
        const uint64_t region_key = crypto::poly_permute_64(seed ^ key_salt, morph_key);
        chained_encrypt(blob.data(), blob.size(), region_key);

        // Region entry: rva^m1, orig_size^m2, key^keymask64,
        // plain_hash = (blob_off ^ m2) | ((comp_size ^ m1) << 32)
        VPackRegion reg{};
        reg.rva        = range_rva ^ m1;
        reg.size       = range_size ^ m2;
        reg.key        = region_key ^ keymask64;
        reg.plain_hash = (static_cast<uint64_t>(blob_cursor) ^ m2) |
                         ((static_cast<uint64_t>(blob.size()) ^ m1) << 32);
        dyn_regions.push_back(reg);

        blob_store.insert(blob_store.end(), blob.begin(), blob.end());
        blob_cursor += static_cast<uint32_t>(blob.size());

        // Strict W^X on disk (L4)
        if (first_sec[sec_idx].Characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE)) {
            first_sec[sec_idx].Characteristics |= (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ);
            first_sec[sec_idx].Characteristics &= ~IMAGE_SCN_MEM_WRITE;
        } else {
            first_sec[sec_idx].Characteristics |= IMAGE_SCN_MEM_READ;
            first_sec[sec_idx].Characteristics &= ~IMAGE_SCN_MEM_EXECUTE;
        }

        // Destroy the plaintext on disk with polymorphic noise
        uint8_t* sec_bytes = data_.data() + sec_raw + offset_in_sec;
        uint64_t nz = crypto::poly_permute_64(seed ^ range_rva, morph_key);
        for (uint32_t i = 0; i < range_size; ++i) {
            nz = rotr64(nz, 11) + kGold64;
            sec_bytes[i] = static_cast<uint8_t>((nz ^ (nz >> 29)) & 0xFF);
        }
    };

    auto encrypt_section_by_name = [&](const char* target_name, uint64_t key_salt) {
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

    if (opts.encrypt_text_section) {
        encrypt_section_by_name(".text", 0x91E3C5A78D2B4F19ULL);
    }
    if (opts.encrypt_vcode_section) {
        encrypt_section_by_name(".vcode", 0xA5A5F0F033CCAA55ULL);
        encrypt_section_by_name(".vinit", 0xD39A81E5C72B4F91ULL);
        encrypt_section_by_name(".vpvlt", 0xC19E73A58B2D4F37ULL);
    }
    if (opts.encrypt_pdata_section) {
        auto& exc_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (exc_dir.VirtualAddress != 0 && exc_dir.Size != 0) {
            vhdr.orig_pdata_rva  = exc_dir.VirtualAddress ^ derive_header_field_mask(seed, kIdPdataRva);
            vhdr.orig_pdata_size = exc_dir.Size ^ derive_header_field_mask(seed, kIdPdataSize);
            exc_dir.VirtualAddress = 0;
            exc_dir.Size           = 0;
        }
        encrypt_section_by_name(".pdata", 0xB583E1A9C72D4F31ULL);
        encrypt_section_by_name(".xdata", 0xC791A3E58B2F4D73ULL);
    }

    // 10. Free the import directory — Stage 2 resolves by hash (L5)
    {
        auto& imp_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (imp_dir.VirtualAddress != 0 && imp_dir.Size != 0) {
            vhdr.code_reloc_count = imp_dir.VirtualAddress ^ derive_header_field_mask(seed, kIdImportRva);
            imp_dir.VirtualAddress = 0;
            imp_dir.Size           = 0;
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = 0;
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size           = 0;
            encrypt_section_by_name(".idata", 0xE593A1C78D2B4F61ULL);
        }
    }

    // Hide Load Config (unchanged)
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress = 0;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size           = 0;

    // 11. Encrypt .rdata reloc/TLS-free intervals (>=16 bytes) via blobs
    for (WORD i = 0; i < num_sec; ++i) {
        char sname[9]{};
        std::memcpy(sname, first_sec[i].Name, 8);
        if (std::strcmp(sname, ".rdata") != 0) continue;

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
                if (tls_dir->StartAddressOfRawData >= nt->OptionalHeader.ImageBase &&
                    tls_dir->EndAddressOfRawData > tls_dir->StartAddressOfRawData) {
                    uint32_t raw_start_rva = static_cast<uint32_t>(tls_dir->StartAddressOfRawData - nt->OptionalHeader.ImageBase);
                    uint32_t raw_len       = static_cast<uint32_t>(tls_dir->EndAddressOfRawData - tls_dir->StartAddressOfRawData);
                    mark_excluded(raw_start_rva, raw_len + 16);
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
        uint64_t salt_counter = 0xF381C9A5E72B4D11ULL;
        while (cur < span) {
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

    // 12. RTTI scrub (unchanged)
    for (WORD i = 0; i < num_sec; ++i) {
        char sname[9]{};
        std::memcpy(sname, first_sec[i].Name, 8);
        if (std::strcmp(sname, ".data") != 0 && std::strcmp(sname, ".rdata") != 0) {
            continue;
        }
        const uint32_t sec_raw  = first_sec[i].PointerToRawData;
        const uint32_t sec_size = first_sec[i].SizeOfRawData;
        if (sec_raw == 0 || sec_raw + sec_size > data_.size() || sec_size < 8) {
            continue;
        }
        uint8_t* sec_ptr = data_.data() + sec_raw;
        uint64_t rtti_rng = crypto::poly_permute_64(seed ^ i, 0xC3A5E7918B2D4F19ULL);

        for (uint32_t off = 0; off + 6 < sec_size; ++off) {
            if (sec_ptr[off] == '.' && sec_ptr[off + 1] == '?' && sec_ptr[off + 2] == 'A' &&
                (sec_ptr[off + 3] == 'V' || sec_ptr[off + 3] == 'U' || sec_ptr[off + 3] == 'W')) {
                uint32_t end_off = off + 4;
                while (end_off < sec_size && end_off - off < 512 &&
                       sec_ptr[end_off] >= 0x20 && sec_ptr[end_off] <= 0x7E) {
                    ++end_off;
                }
                if (end_off < sec_size && sec_ptr[end_off] == 0x00 && (end_off - off) >= 6) {
                    for (uint32_t k = off; k < end_off; ++k) {
                        rtti_rng = rotr64(rtti_rng, 13) + kGold64;
                        uint8_t b = static_cast<uint8_t>((rtti_rng ^ (rtti_rng >> 29)) & 0xFFu);
                        if (b == 0x00) b = 0x5Au;
                        sec_ptr[k] = b;
                    }
                    off = end_off;
                }
            }
        }
    }

    // 13. Section name masquerade (unchanged)
    for (WORD i = 0; i < num_sec; ++i) {
        char sname[9]{};
        std::memcpy(sname, first_sec[i].Name, 8);
        if (std::strcmp(sname, ".vcode") == 0 ||
            std::strcmp(sname, ".vinit") == 0 ||
            std::strcmp(sname, ".vpvlt") == 0 ||
            std::strcmp(sname, ".pdata") == 0 ||
            std::strcmp(sname, ".xdata") == 0 ||
            std::strcmp(sname, ".idata") == 0 ||
            std::strcmp(sname, ".eh_fram") == 0 ||
            std::strcmp(sname, ".fptable") == 0) {
            const char suffix = (i < 10)
                ? static_cast<char>('0' + i)
                : static_cast<char>('a' + ((i - 10) % 26));
            char obf_name[8]{'.', 's', 'b', 'l', suffix, 0, 0, 0};
            std::memcpy(first_sec[i].Name, obf_name, 8);
        }
    }

    // 14. Build the stub section payload
    std::vector<uint8_t> vpack_sec_data = build_vpack_section_payload(
        vhdr, seed, dyn_regions, dyn_relocs, blob_store, new_sec_va,
        opts.stub_anti_debug, stolen, tls_cb_pair
    );

    const uint32_t new_sec_raw_ptr  = align_up(max_raw_end, file_align);
    const uint32_t new_sec_vsize    = static_cast<uint32_t>(vpack_sec_data.size());
    const uint32_t new_sec_raw_size = align_up(new_sec_vsize, file_align);

    if (data_.size() < new_sec_raw_ptr + new_sec_raw_size) {
        data_.resize(new_sec_raw_ptr + new_sec_raw_size, 0);
    }
    std::memcpy(data_.data() + new_sec_raw_ptr, vpack_sec_data.data(), vpack_sec_data.size());

    nt        = reinterpret_cast<IMAGE_NT_HEADERS64*>(data_.data() + nt_headers_offset_);
    first_sec = IMAGE_FIRST_SECTION(nt);

    IMAGE_SECTION_HEADER& new_sec = first_sec[num_sec];
    std::memset(&new_sec, 0, sizeof(IMAGE_SECTION_HEADER));
    {
        constexpr char kAlphabet[] = "abcdefghijklmnopqrstuvwxyz0123456789";
        uint64_t name_rng = crypto::poly_permute_64(public_salt, 0x7F4A7C159E3779B9ULL);
        char rand_sec_name[8]{'.', 0, 0, 0, 0, 0, 0, 0};
        for (int c = 1; c <= 5; ++c) {
            name_rng = rotr64(name_rng, 11) + kGold64;
            rand_sec_name[c] = kAlphabet[name_rng % (sizeof(kAlphabet) - 1)];
        }
        std::memcpy(new_sec.Name, rand_sec_name, 8);
    }
    new_sec.Misc.VirtualSize = new_sec_vsize;
    new_sec.VirtualAddress   = new_sec_va;
    new_sec.SizeOfRawData    = new_sec_raw_size;
    new_sec.PointerToRawData = new_sec_raw_ptr;
    // RWX AT LOAD (UPX-style): the stub MUST be writable at process start because Stage 1/2
    // write the header slots and self-decrypt/self-wipe their own code pages. Calling
    // VirtualProtect on the section CONTAINING the running stub fast-fails on Windows 11
    // (kernelbase self-modify guard, FAST_FAIL 0x57). The SDK re-seals this section to RX
    // right after init (finalize_vpack_section_in_memory), restoring strict W^X at runtime.
    new_sec.Characteristics  = IMAGE_SCN_CNT_CODE | IMAGE_SCN_CNT_INITIALIZED_DATA |
                               IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ |
                               IMAGE_SCN_MEM_WRITE;

    nt->FileHeader.NumberOfSections = static_cast<WORD>(num_sec + 1);
    nt->OptionalHeader.SizeOfImage  = align_up(new_sec_va + new_sec_vsize, sec_align);

    uint32_t new_ep_rva = orig_ep_plain;
    if (opts.inject_entry_stub) {
        new_ep_rva = new_sec_va + kEpStubOffset;
        nt->OptionalHeader.AddressOfEntryPoint = new_ep_rva;
    }

    nt->OptionalHeader.CheckSum = 0;

    res.success            = true;
    res.message            = "Successfully packed PE64 (LZSS+ChainedCipher regions, hashed IAT, stolen OEP, W^X, ASLR+NX)";
    res.original_entry_rva = orig_ep_plain;
    res.new_entry_rva      = new_ep_rva;
    res.encrypted_regions  = static_cast<uint32_t>(dyn_regions.size());
    res.stripped_sections  = stripped_count;
    res.output_size        = data_.size();
    return res;
}

} // namespace vpack::pe
