#pragma once

#include "vpack/config.h"
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace vpack::pe {

struct SectionInfo {
    std::string name;
    uint32_t    virtual_address = 0;
    uint32_t    virtual_size = 0;
    uint32_t    raw_offset = 0;
    uint32_t    raw_size = 0;
    uint32_t    characteristics = 0;
};

struct PackOptions {
    bool     encrypt_text_section  = true;
    bool     encrypt_vcode_section = true;
    bool     encrypt_pdata_section = true;
    bool     strip_symbols_and_debug = true;
    bool     inject_entry_stub     = true;
    bool     stub_anti_debug       = true;
    uint32_t protection_flags      = PROT_DEFAULT;
    uint64_t custom_seed           = 0;
};

struct PackResult {
    bool        success = false;
    std::string message;
    uint32_t    original_entry_rva = 0;
    uint32_t    new_entry_rva = 0;
    uint32_t    encrypted_regions = 0;
    uint32_t    stripped_sections = 0;
    size_t      output_size = 0;
};

class PeImage {
public:
    PeImage() = default;

    bool load_from_file(const std::string& path, std::string* err = nullptr);
    bool load_from_memory(std::vector<uint8_t> data, std::string* err = nullptr);
    bool save_to_file(const std::string& path, std::string* err = nullptr) const;

    bool is_valid_pe64() const noexcept { return valid_pe64_; }
    uint64_t image_base() const noexcept;
    uint32_t entry_point_rva() const noexcept;
    uint32_t size_of_image() const noexcept;

    std::vector<SectionInfo> list_sections() const;
    bool find_section(const std::string& name, SectionInfo& out_sec) const;
    bool rva_to_file_offset(uint32_t rva, uint32_t& out_offset) const noexcept;

    PackResult pack(const PackOptions& opts = PackOptions{});

    bool is_already_packed(VPackHeader* out_header = nullptr) const noexcept;

    const std::vector<uint8_t>& bytes() const noexcept { return data_; }

private:
    std::vector<uint8_t> data_;
    uint32_t             nt_headers_offset_ = 0;
    bool                 valid_pe64_ = false;
};

} // namespace vpack::pe
