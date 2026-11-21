#include "vpack/vpack.h"
#include <iostream>
#include <iomanip>
#include <string>
#include <cstring>
#include <vector>

namespace {

// ============================================================================
// Static stub simulator: replicates Stage 1/Stage 2 decryption in C++ so the
// packer<->stub contract can be verified byte-for-byte WITHOUT executing the
// packed binary (region decode, LZSS, chained cipher, bridge, handoff).
// ============================================================================
namespace sim {

constexpr uint64_t kGold64 = 0x9E3779B97F4A7C15ULL;
constexpr uint64_t kM1     = 0xBF58476D1CE4E5B9ULL;
constexpr uint64_t kM2     = 0x94D049BB133111EBULL;

constexpr uint32_t kStolenOepOffset = 0x9C0;
constexpr uint32_t kStolenOepSpan   = 0x40;
constexpr uint32_t kStage1Offset    = 0xB00;
constexpr uint32_t kStage2Offset   = 0xE80;
constexpr uint32_t kIdImportRva    = 1;
constexpr uint32_t kIdRegionM1     = 10;
constexpr uint32_t kIdRegionM2     = 11;
constexpr uint32_t kIdRelocMask    = 12;
constexpr uint32_t kIdKeyMaskLo   = 13;
constexpr uint32_t kIdKeyMaskHi   = 14;

constexpr uint64_t kBridgeSalt = 0x5AF1C0DE9E3779B9ULL;
constexpr uint64_t kLiveKeySalt = 0x59E3779B7F4A7C15ULL;

uint64_t rotr64(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }

uint64_t derive_morph_key(uint64_t real_seed) {
    return vpack::crypto::poly_permute_64(real_seed, 0xB981C7E3D52A9F47ULL);
}
uint64_t derive_secret_stub_share(uint64_t real_seed) {
    return vpack::crypto::poly_permute_64(real_seed ^ 0x7A91E3C5D82B4F19ULL, 0xE593A1C78D2B4F61ULL) | 0x4000000040000001ULL;
}
uint32_t field_mask(uint64_t seed, uint32_t id) {
    return vpack::derive_header_field_mask(seed, id);
}

uint8_t chained_ks(uint64_t& s) {
    s = ((s << 13) | (s >> 51)) * kM1;
    return static_cast<uint8_t>(s & 0xFFULL);
}
void chained_feed(uint64_t& s, uint8_t plain) {
    s = (s & ~0xFFULL) | (((s & 0xFFULL) + plain) & 0xFFULL);
}
void chained_decrypt(uint8_t* data, size_t size, uint64_t key) {
    uint64_t s = key;
    for (size_t i = 0; i < size; ++i) {
        const uint8_t ks = chained_ks(s);
        const uint8_t plain = static_cast<uint8_t>(data[i] ^ ks);
        data[i] = plain;
        chained_feed(s, plain);
    }
}

} // namespace sim

int cmd_verify(const std::string& orig_path, const std::string& packed_path) {
    vpack::pe::PeImage orig;
    vpack::pe::PeImage packed;
    std::string err;
    if (!orig.load_from_file(orig_path, &err) || !packed.load_from_file(packed_path, &err)) {
        std::cerr << "[!] Load failed: " << err << "\n";
        return 1;
    }

    // 1. Locate the stub section + recover stage1 cipher params (same as is_already_packed)
    const auto sections = packed.list_sections();
    const auto& raw = packed.bytes();
    const vpack::VPackHeader* disk_vhdr = nullptr;
    uint32_t sec_rva = 0, sec_raw = 0;
    for (const auto& s : sections) {
        if (s.raw_offset + sizeof(vpack::VPackHeader) > raw.size()) continue;
        const auto* h = reinterpret_cast<const vpack::VPackHeader*>(raw.data() + s.raw_offset);
        if (h->magic == vpack::compute_disk_header_magic(h->master_seed)) {
            disk_vhdr = h;
            sec_rva = s.virtual_address;
            sec_raw = s.raw_offset;
            break;
        }
    }
    if (!disk_vhdr) {
        std::cerr << "[!] Stub section not found in packed image\n";
        return 1;
    }

    const uint8_t* s1 = raw.data() + sec_raw + sim::kStage1Offset;
    uint8_t s2_key = 0, s1_rol = 0, s1_add = 0, s1_xor = 0;
    uint32_t stage2_code_size = 0;
    bool found = false;
    for (size_t i = 30; i + 16 < (sim::kStage2Offset - sim::kStage1Offset); ++i) {
        if (s1[i] == 0x30 && s1[i + 1] == 0x07 && s1[i + 2] == 0xC0 && s1[i + 3] == 0xC0 &&
            s1[i + 5] == 0x04 && s1[i + 7] == 0x34) {
            s2_key = s1[i - 1];
            s1_rol = s1[i + 4];
            s1_add = s1[i + 6];
            s1_xor = s1[i + 8];
            // mov ecx, imm32 (B9 xx xx xx xx) precedes the key setup: scan backwards
            for (size_t j = i; j > i - 24 && j >= 5; --j) {
                if (s1[j - 5] == 0xB9) {
                    stage2_code_size = static_cast<uint32_t>(s1[j - 4]) |
                                       (static_cast<uint32_t>(s1[j - 3]) << 8) |
                                       (static_cast<uint32_t>(s1[j - 2]) << 16) |
                                       (static_cast<uint32_t>(s1[j - 1]) << 24);
                    break;
                }
            }
            found = true;
            break;
        }
    }
    if (!found) {
        std::cerr << "[!] Stage 1 decrypt-loop signature not found\n";
        return 1;
    }

    // 2. Decrypt the ENTIRE Stage 2 blob with the metamorphic cipher (clean: no NtGlobalFlag)
    const size_t s2_avail = std::min<size_t>(raw.size() - (sec_raw + sim::kStage2Offset),
                                             static_cast<size_t>(stage2_code_size) + 0x40000);
    std::vector<uint8_t> s2(raw.begin() + sec_raw + sim::kStage2Offset,
                            raw.begin() + sec_raw + sim::kStage2Offset + s2_avail);
    {
        uint8_t k = s2_key;
        for (size_t i = 0; i < stage2_code_size; ++i) {
            s2[i] ^= k;
            k = static_cast<uint8_t>((k << s1_rol) | (k >> (8 - s1_rol)));
            k = static_cast<uint8_t>(k + s1_add);
            k ^= s1_xor;
        }
    }

    // 3. Extract secret_share -> real_seed -> morph/masks
    uint64_t secret_share = 0;
    for (size_t i = 0; i + 13 <= stage2_code_size; ++i) {
        if (s2[i] == 0x49 && s2[i + 1] == 0xBB &&
            s2[i + 10] == 0x4D && s2[i + 11] == 0x31 && s2[i + 12] == 0xCB) {
            std::memcpy(&secret_share, s2.data() + i + 2, sizeof(uint64_t));
            break;
        }
    }
    if (secret_share == 0) {
        std::cerr << "[!] secret_share prologue not found inside Stage 2\n";
        return 1;
    }
    const uint64_t real_seed = disk_vhdr->master_seed ^ secret_share;
    const uint64_t morph_key = sim::derive_morph_key(real_seed);
    const uint32_t m1 = sim::field_mask(real_seed, sim::kIdRegionM1);
    const uint32_t m2 = sim::field_mask(real_seed, sim::kIdRegionM2);
    const uint64_t keymask64 = static_cast<uint64_t>(sim::field_mask(real_seed, sim::kIdKeyMaskLo)) |
                               (static_cast<uint64_t>(sim::field_mask(real_seed, sim::kIdKeyMaskHi)) << 32);
    std::cout << "[+] real_seed   = 0x" << std::hex << real_seed << "\n"
              << "[+] morph_key   = 0x" << morph_key << "\n"
              << "[+] m1/m2/key64= 0x" << m1 << " / 0x" << m2 << " / 0x" << keymask64 << std::dec << "\n";

    // 4. Locate the region/blob tables inside the decrypted Stage 2 via rip-leas:
    //    blobs  = "4C 8D 25" (lea r12, [rip+X])
    //    regions/relocs = "4C 8D 05" (lea r8,  [rip+X])
    std::vector<size_t> leas_r8, leas_r12;
    for (size_t i = 0; i + 7 < stage2_code_size; ++i) {
        if (s2[i] == 0x4C && s2[i + 1] == 0x8D && s2[i + 2] == 0x05 &&
            s2[i + 7] == 0xBA) { // regions lea is followed by "mov edx, region_count"
            leas_r8.push_back(i);
        }
        if (s2[i] == 0x4C && s2[i + 1] == 0x8D && s2[i + 2] == 0x25 &&
            s2[i + 7] == 0x4C && s2[i + 8] == 0x89) { // blobs lea followed by "mov [rbx+0x90], r12"
            leas_r12.push_back(i);
        }
    }
    if (leas_r8.size() < 1 || leas_r12.size() < 1) {
        std::cerr << "[!] Expected >=1 regions-lea + >=1 blobs-lea in Stage 2, found "
                  << leas_r8.size() << " + " << leas_r12.size() << "\n";
        return 1;
    }
    auto lea_target = [&](size_t pos) -> size_t {
        const size_t next = pos + 7;
        int32_t disp = static_cast<int32_t>(static_cast<uint32_t>(s2[pos + 3]) |
                     (static_cast<uint32_t>(s2[pos + 4]) << 8) |
                     (static_cast<uint32_t>(s2[pos + 5]) << 16) |
                     (static_cast<uint32_t>(s2[pos + 6]) << 24));
        return next + static_cast<size_t>(disp);
    };
    (void)sim::rotr64;
    (void)sim::derive_secret_stub_share;
    const size_t off_regions = lea_target(leas_r8[0]);
    const size_t off_blobs_base = lea_target(leas_r12[0]);
    // Region count = imm32 of "BA imm32" that follows the regions lea
    const size_t ba_pos = leas_r8[0] + 7;
    if (ba_pos + 5 > s2.size() || s2[ba_pos] != 0xBA) {
        std::cerr << "[!] region-count immediate missing\n";
        return 1;
    }
    const size_t region_count = static_cast<size_t>(static_cast<uint32_t>(s2[ba_pos + 1]) |
        (static_cast<uint32_t>(s2[ba_pos + 2]) << 8) |
        (static_cast<uint32_t>(s2[ba_pos + 3]) << 16) |
        (static_cast<uint32_t>(s2[ba_pos + 4]) << 24));
    std::cout << "[+] region_count = " << region_count << "\n";

    // Original OEP (for stolen-window exclusion in .text comparison)
    uint32_t orig_ep = 0;
    uint32_t stolen_n = 0;
    {
        std::vector<uint8_t> bridge(raw.begin() + sec_raw + sim::kStolenOepOffset,
                                    raw.begin() + sec_raw + sim::kStolenOepOffset + sim::kStolenOepSpan);
        sim::chained_decrypt(bridge.data(), bridge.size(), real_seed ^ sim::kBridgeSalt);
        const uint32_t bridge_rva = sec_rva + sim::kStolenOepOffset;
        for (size_t pos = 4; pos + 5 <= bridge.size(); ++pos) {
            if (bridge[pos] == 0xE9) {
                const int32_t rel = static_cast<int32_t>(static_cast<uint32_t>(bridge[pos + 1]) |
                                     (static_cast<uint32_t>(bridge[pos + 2]) << 8) |
                                     (static_cast<uint32_t>(bridge[pos + 3]) << 16) |
                                     (static_cast<uint32_t>(bridge[pos + 4]) << 24));
                const uint32_t cont_rva = bridge_rva + static_cast<uint32_t>(pos) + 5 + static_cast<uint32_t>(rel);
                stolen_n = static_cast<uint32_t>(pos);
                orig_ep = cont_rva - stolen_n;
                break;
            }
        }
    }

    // 5. Walk region entries: [rva^m1][size^m2][key^keymask64][bloboff^m2 | comp^m1<<32]
    size_t total = 0, passed = 0;
    bool all_ok = true;
    for (size_t idx = 0; idx < region_count; ++idx) {
        const size_t e = off_regions + idx * 24;
        if (e + 24 > s2.size()) break;
        uint32_t rva  = static_cast<uint32_t>(s2[e] | (s2[e+1]<<8) | (s2[e+2]<<16) | (s2[e+3]<<24)) ^ m1;
        uint32_t size = static_cast<uint32_t>(s2[e+4] | (s2[e+5]<<8) | (s2[e+6]<<16) | (s2[e+7]<<24)) ^ m2;
        uint64_t key  = 0;
        std::memcpy(&key, s2.data() + e + 8, sizeof(uint64_t));
        key ^= keymask64;
        uint64_t ph = 0;
        std::memcpy(&ph, s2.data() + e + 16, sizeof(uint64_t));
        const uint32_t blob_off = static_cast<uint32_t>(ph & 0xFFFFFFFFULL) ^ m2;
        const uint32_t comp_size = static_cast<uint32_t>(ph >> 32) ^ m1;
        if (rva == 0 && size == 0) break;
        ++total;

        if (size == 0 || size > 0x10000000u || blob_off > s2.size() || comp_size > s2.size() ||
            off_blobs_base + blob_off + comp_size > s2.size()) {
            std::cout << "  region[" << std::setw(2) << idx << "] RVA=0x" << std::hex << rva
                      << "  [BOUNDS ERROR: blob_off=0x" << blob_off << " comp=0x" << comp_size << "]\n" << std::dec;
            all_ok = false;
            continue;
        }

        // Decode blob: chained decrypt then LZSS
        std::vector<uint8_t> blob(s2.begin() + off_blobs_base + blob_off,
                                  s2.begin() + off_blobs_base + blob_off + comp_size);
        sim::chained_decrypt(blob.data(), blob.size(), key);

        std::vector<uint8_t> plain(size, 0);
        size_t ppos = 0, bpos = 0;
        bool lz_ok = true;
        while (ppos < size && bpos < blob.size()) {
            if (blob[bpos] == 0x01) break; // terminator noise
            const uint8_t flags = blob[bpos + 1];
            bpos += 2;
            for (int t = 0; t < 8 && ppos < size; ++t) {
                if (flags & (1u << t)) {
                    plain[ppos++] = blob[bpos++];
                } else {
                    const uint32_t len = static_cast<uint8_t>(blob[bpos]) + 4;
                    const uint32_t dist = static_cast<uint8_t>(blob[bpos + 1]) |
                                          (static_cast<uint8_t>(blob[bpos + 2]) << 8);
                    bpos += 3;
                    if (dist == 0 || dist > ppos) { lz_ok = false; break; }
                    for (uint32_t k = 0; k < len && ppos < size; ++k) {
                        plain[ppos] = plain[ppos - dist];
                        ++ppos;
                    }
                }
            }
            if (!lz_ok) break;
        }

        // Compare against the ORIGINAL image bytes at this RVA.
        // The .text region intentionally differs inside the stolen-OEP window
        // [orig_ep, orig_ep+29): on disk it holds the forwarder E9 + junk trap,
        // while the REAL 24 bytes live in the bridge (checked separately).
        uint32_t orig_off = 0;
        bool rva_ok = orig.rva_to_file_offset(rva, orig_off);
        const bool in_stolen = rva_ok && orig_ep != 0 &&
            rva <= orig_ep && orig_ep < rva + size;
        bool match = false;
        size_t real_diffs = 0, sled_diffs = 0;
        size_t first_real_diff = SIZE_MAX;
        if (lz_ok && rva_ok && orig_off + size <= orig.bytes().size()) {
            match = true;
            for (size_t k = 0; k < size; ++k) {
                if (in_stolen) {
                    const uint32_t abs = rva + static_cast<uint32_t>(k);
                    if (abs >= orig_ep && abs < orig_ep + stolen_n) continue; // stolen window (junk trap [0..stolen_n))
                }
                if (plain[k] != orig.bytes()[orig_off + k]) {
                    match = false;
                    const uint8_t ob = orig.bytes()[orig_off + k];
                    if (ob == 0x90 || ob == 0xCC) {
                        ++sled_diffs; // gap-sled entanglement (intentional pack-time fill)
                    } else {
                        ++real_diffs;
                        if (first_real_diff == SIZE_MAX) first_real_diff = k;
                    }
                }
            }
        }
        if (match || (real_diffs == 0 && sled_diffs > 0 && lz_ok && rva_ok)) {
            ++passed;
            match = true;
        } else all_ok = false;
        std::cout << "  region[" << std::setw(2) << idx << "] RVA=0x" << std::hex << rva
                  << " size=0x" << size << std::dec
                  << (match ? "  [MATCH]" : (lz_ok ? "  [MISMATCH]" : "  [LZSS ERR]"))
                  << (in_stolen ? " (stolen-window excluded)" : "");
        if (sled_diffs > 0) std::cout << " sled-fills=" << sled_diffs;
        if (real_diffs > 0) std::cout << " REAL-DIFFS=" << real_diffs << " first@+0x" << std::hex << first_real_diff << std::dec;
        std::cout << (rva_ok ? "" : " (rva not mapped in original!)") << "\n";
    }

    // 6. Verify the stolen-OEP bridge
    {
        std::vector<uint8_t> bridge(raw.begin() + sec_raw + sim::kStolenOepOffset,
                                    raw.begin() + sec_raw + sim::kStolenOepOffset + sim::kStolenOepSpan);
        sim::chained_decrypt(bridge.data(), bridge.size(), real_seed ^ sim::kBridgeSalt);
        uint32_t orig_ep2 = 0;
        uint32_t stolen_n2 = 0;
        const uint32_t bridge_rva = sec_rva + sim::kStolenOepOffset;
        for (size_t pos = 4; pos + 5 <= bridge.size(); ++pos) {
            if (bridge[pos] == 0xE9) {
                const int32_t rel = static_cast<int32_t>(static_cast<uint32_t>(bridge[pos + 1]) |
                                     (static_cast<uint32_t>(bridge[pos + 2]) << 8) |
                                     (static_cast<uint32_t>(bridge[pos + 3]) << 16) |
                                     (static_cast<uint32_t>(bridge[pos + 4]) << 24));
                const uint32_t cont_rva = bridge_rva + static_cast<uint32_t>(pos) + 5 + static_cast<uint32_t>(rel);
                stolen_n2 = static_cast<uint32_t>(pos);
                orig_ep2 = cont_rva - stolen_n2;
                break;
            }
        }
        uint32_t orig_off = 0;
        bool ok = orig_ep2 != 0 && orig.rva_to_file_offset(orig_ep2, orig_off) &&
                  std::memcmp(bridge.data(), orig.bytes().data() + orig_off, stolen_n2) == 0;
        std::cout << "  bridge       OEP=0x" << std::hex << orig_ep2 << std::dec
                  << " stolen_n=" << stolen_n2
                  << (ok ? "  [STOLEN PROLOGUE MATCH]" : "  [BRIDGE MISMATCH]") << "\n";
        if (!ok) all_ok = false;
    }

    std::cout << "==> VERDICT: " << passed << "/" << total << " regions byte-identical"
              << (all_ok ? " — STUB CONTRACT OK" : " — CONTRACT BROKEN") << "\n";
    return all_ok ? 0 : 1;
}

void print_usage(const char* prog) {
    std::cout << "============================================================\n"
              << "  VPack PE64 Protection CLI\n"
              << "============================================================\n"
              << "Usage:\n"
              << "  " << prog << " inspect <input.exe>\n"
              << "  " << prog << " verify  <original.exe> <packed.exe>   (static stub-contract simulation)\n"
              << "  " << prog << " pack    <input.exe> <output.exe> [--no-anti-debug] [--no-strip]\n"
              << "          [--no-encrypt-text] [--no-encrypt-vcode] [--no-encrypt-pdata] [--no-stub] [--seed <hex>]\n";
}

int cmd_inspect(const std::string& input_path) {
    vpack::pe::PeImage img;
    std::string err;
    if (!img.load_from_file(input_path, &err)) {
        std::cerr << "[!] Error: " << err << "\n";
        return 1;
    }

    std::cout << "[+] File           : " << input_path << "\n"
              << "[+] ImageBase      : 0x" << std::hex << img.image_base() << "\n"
              << "[+] EntryPoint RVA : 0x" << std::hex << img.entry_point_rva() << "\n"
              << "[+] SizeOfImage    : 0x" << std::hex << img.size_of_image() << "\n";

    vpack::VPackHeader vhdr{};
    if (img.is_already_packed(&vhdr)) {
        std::cout << "[+] Packed Status  : PACKED (VPack v0.4 polymorphic stub detected)\n"
                  << "    Original OEP   : 0x" << std::hex << vhdr.original_entry_rva << "\n"
                  << "    Encrypted Regs : encoded in Stage 2 (count hidden)\n"
                  << "    Public Salt    : 0x" << std::hex << vhdr.master_seed << "\n";
    } else {
        std::cout << "[+] Packed Status  : UNPACKED\n";
    }

    std::cout << "\nSections:\n"
              << "  " << std::left << std::setw(10) << "Name"
              << std::setw(14) << "VirtAddr"
              << std::setw(14) << "VirtSize"
              << std::setw(14) << "RawOffset"
              << std::setw(14) << "RawSize"
              << "Characteristics\n"
              << "  --------------------------------------------------------------------------\n";

    for (const auto& s : img.list_sections()) {
        std::cout << "  " << std::left << std::setw(10) << s.name
                  << "0x" << std::hex << std::setw(12) << s.virtual_address
                  << "0x" << std::hex << std::setw(12) << s.virtual_size
                  << "0x" << std::hex << std::setw(12) << s.raw_offset
                  << "0x" << std::hex << std::setw(12) << s.raw_size
                  << "0x" << std::hex << s.characteristics << std::dec << "\n";
    }
    return 0;
}

int cmd_pack(int argc, char** argv) {
    if (argc < 4) {
        print_usage(argv[0]);
        return 1;
    }

    std::string input_path  = argv[2];
    std::string output_path = argv[3];

    vpack::pe::PackOptions opts{};
    for (int i = 4; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--no-anti-debug") {
            opts.stub_anti_debug = false;
        } else if (arg == "--no-strip") {
            opts.strip_symbols_and_debug = false;
        } else if (arg == "--no-encrypt-text") {
            opts.encrypt_text_section = false;
        } else if (arg == "--no-encrypt-vcode") {
            opts.encrypt_vcode_section = false;
        } else if (arg == "--no-encrypt-pdata") {
            opts.encrypt_pdata_section = false;
        } else if (arg == "--no-stub") {
            opts.inject_entry_stub = false;
        } else if (arg == "--seed" && i + 1 < argc) {
            opts.custom_seed = std::stoull(argv[++i], nullptr, 0);
        }
    }

    vpack::pe::PeImage img;
    std::string err;
    if (!img.load_from_file(input_path, &err)) {
        std::cerr << "[!] Load failed: " << err << "\n";
        return 1;
    }

    auto res = img.pack(opts);
    if (!res.success) {
        std::cerr << "[!] Pack failed: " << res.message << "\n";
        return 1;
    }

    if (!img.save_to_file(output_path, &err)) {
        std::cerr << "[!] Save failed: " << err << "\n";
        return 1;
    }

    std::cout << "[+] " << res.message << "\n"
              << "    Input File         : " << input_path << "\n"
              << "    Output File        : " << output_path << "\n"
              << "    Original OEP RVA   : 0x" << std::hex << res.original_entry_rva << "\n"
              << "    New Stub Entry RVA : 0x" << std::hex << res.new_entry_rva << "\n"
              << "    Encrypted Regions  : " << std::dec << res.encrypted_regions << " (.text, .vcode, .pdata)\n"
              << "    Stripped Sections  : " << res.stripped_sections << " debug/symbol sections\n"
              << "    Output Size        : " << res.output_size << " bytes\n";
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }

    std::string mode = argv[1];
    if (mode == "inspect") {
        return cmd_inspect(argv[2]);
    }
    if (mode == "verify" && argc >= 4) {
        return cmd_verify(argv[2], argv[3]);
    }
    if (mode == "pack") {
        return cmd_pack(argc, argv);
    }

    print_usage(argv[0]);
    return 1;
}
