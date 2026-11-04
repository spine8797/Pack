#pragma once

#include <cstdint>
#include <cstddef>

#if defined(_MSC_VER)
    #define VPACK_NOINLINE __declspec(noinline)
    #define VPACK_FORCEINLINE __forceinline
    #pragma section(".vcode", execute, read, write)
    #define VPACK_CODE __declspec(code_seg(".vcode")) VPACK_NOINLINE
#elif defined(__GNUC__) || defined(__clang__)
    #define VPACK_NOINLINE __attribute__((noinline))
    #define VPACK_FORCEINLINE __attribute__((always_inline)) inline
    #define VPACK_CODE __attribute__((section(".vcode"), noinline, used))
#else
    #define VPACK_NOINLINE
    #define VPACK_FORCEINLINE inline
    #define VPACK_CODE
#endif

namespace vpack {

constexpr uint32_t VPACK_MAGIC           = 0x4B435056; // "VPCK"
constexpr uint16_t VPACK_VERSION         = 0x0200;
constexpr size_t   VPACK_MAX_REGIONS     = 24;
constexpr size_t   VPACK_MAX_CODE_RELOCS = 416;

enum ProtectionFlags : uint32_t {
    PROT_NONE               = 0,
    PROT_ANTI_DEBUG         = 1u << 0,
    PROT_ANTI_DUMP          = 1u << 1,
    PROT_HIDE_THREAD        = 1u << 2,
    PROT_CLEAR_HWBP         = 1u << 3,
    PROT_VERIFY_INTEGRITY   = 1u << 4,
    PROT_TAMPER_IMAGE_SIZE  = 1u << 5,
    PROT_STUB_ANTI_DEBUG    = 1u << 6,
    PROT_DEFAULT            = PROT_ANTI_DEBUG | PROT_ANTI_DUMP | PROT_HIDE_THREAD |
                              PROT_CLEAR_HWBP | PROT_VERIFY_INTEGRITY | PROT_TAMPER_IMAGE_SIZE |
                              PROT_STUB_ANTI_DEBUG
};

#pragma pack(push, 1)
struct VPackRegion {
    uint32_t rva;
    uint32_t size;
    uint64_t key;
    uint64_t plain_hash;
};

struct VPackHeader {
    uint32_t    magic;                  // 0x00
    uint16_t    version;                // 0x04
    uint16_t    region_count;           // 0x06
    uint32_t    flags;                  // 0x08
    uint32_t    original_entry_rva;     // 0x0C
    uint64_t    master_seed;            // 0x10
    uint64_t    preferred_image_base;   // 0x18
    uint32_t    orig_tls_callback_rva;  // 0x20
    uint32_t    code_reloc_count;       // 0x24
    uint32_t    orig_pdata_rva;         // 0x28
    uint32_t    orig_pdata_size;        // 0x2C
    VPackRegion regions[VPACK_MAX_REGIONS];               // 0x30
    uint32_t    code_reloc_rvas[VPACK_MAX_CODE_RELOCS];   // 0xF0
    uint32_t    orig_import_rva;                          // 0x8F0
};
#pragma pack(pop)

} // namespace vpack
