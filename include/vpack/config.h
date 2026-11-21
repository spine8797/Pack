#pragma once

#include <cstdint>
#include <cstddef>

#if defined(_MSC_VER)
    #define VPACK_NOINLINE __declspec(noinline)
    #define VPACK_FORCEINLINE __forceinline
    #pragma code_seg(".vcode")
    #pragma code_seg(".vinit")
    #pragma code_seg(".vpvlt")
    #pragma code_seg()
    #define VPACK_CODE __declspec(code_seg(".vcode")) VPACK_NOINLINE
    #define VPACK_INIT_CODE __declspec(code_seg(".vinit")) VPACK_NOINLINE
    #define VPACK_VAULT_CODE __declspec(code_seg(".vpvlt")) VPACK_NOINLINE
#elif defined(__GNUC__) || defined(__clang__)
    #define VPACK_NOINLINE __attribute__((noinline))
    #define VPACK_FORCEINLINE __attribute__((always_inline)) inline
    #define VPACK_CODE __attribute__((section(".vcode"), noinline, used))
    #define VPACK_INIT_CODE __attribute__((section(".vinit"), noinline, used))
    #define VPACK_VAULT_CODE __attribute__((section(".vpvlt"), noinline, used))
#else
    #define VPACK_NOINLINE
    #define VPACK_FORCEINLINE inline
    #define VPACK_CODE
    #define VPACK_INIT_CODE
    #define VPACK_VAULT_CODE
#endif

namespace vpack {

constexpr uint32_t VPACK_MAGIC           = 0x4B435056; // Legacy symbol kept for API compatibility; never emitted on disk
constexpr uint16_t VPACK_VERSION         = 0x0400;
constexpr size_t   VPACK_MAX_REGIONS     = 24;
constexpr size_t   VPACK_MAX_CODE_RELOCS = 415;

// Non-linear SplitMix64 authentication tags (eliminates static 'VPCK' XOR and plaintext version signatures)
constexpr uint32_t compute_disk_header_magic(uint64_t public_salt) noexcept {
    uint64_t z = public_salt + 0x9E3779B97F4A7C15ULL;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    z ^= (z >> 31);
    return static_cast<uint32_t>(z & 0xFFFFFFFFULL) ^ 0x71D9A3C5u;
}

constexpr uint16_t compute_disk_header_ver(uint64_t public_salt) noexcept {
    uint64_t z = (public_salt ^ 0xD1B54A32D192ED03ULL) * 0x94D049BB133111EBULL;
    z ^= (z >> 33);
    return static_cast<uint16_t>((z & 0xFFFEULL) | 1ULL);
}

constexpr uint32_t compute_runtime_handoff_magic(uint64_t runtime_seed) noexcept {
    uint64_t z = (runtime_seed ^ 0x6C62272E07BB0142ULL) * 0xBF58476D1CE4E5B9ULL;
    z ^= (z >> 29);
    return static_cast<uint32_t>(z & 0xFFFFFFFFULL);
}

// Header field-mask domain ids (SHARED CONTRACT: packer C++ <-> Stage 2 asm <-> SDK C++)
// Domain-separated SplitMix64 masks prevent two zero metadata fields from leaking
// identical masks, and the SDK masks are bound to runtime state (ASLR base + debug bits).
constexpr uint32_t kIdFlags     = 0;   // [0x08] protection flags (noise-masked on disk)
constexpr uint32_t kIdImportRva = 1;   // [0x24] original import descriptor RVA
constexpr uint32_t kIdPdataRva  = 2;   // [0x28] original .pdata RVA
constexpr uint32_t kIdPdataSize = 3;   // [0x2C] original .pdata size
constexpr uint32_t kIdTlsCb     = 4;   // [0x20] original TLS callback RVA
constexpr uint32_t kIdVcodeRva  = 5;   // [0x8F0]
constexpr uint32_t kIdVcodeSize = 6;   // [0x8F4]
constexpr uint32_t kIdVinitRva  = 7;   // [0x8F8]
constexpr uint32_t kIdVinitSize = 8;   // [0x8FC]

// Per-field domain-separated 32-bit mask (prevents two zero metadata fields from leaking identical masks)
constexpr uint32_t derive_header_field_mask(uint64_t seed, uint32_t field_id) noexcept {
    uint64_t z = seed ^ (static_cast<uint64_t>(field_id + 1u) * 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    z ^= (z >> 31);
    return static_cast<uint32_t>(z & 0xFFFFFFFFULL);
}

enum ProtectionFlags : uint32_t {
    PROT_NONE               = 0,
    PROT_ANTI_DEBUG         = 1u << 0,
    PROT_ANTI_DUMP          = 1u << 1,
    PROT_HIDE_THREAD        = 1u << 2,
    PROT_CLEAR_HWBP         = 1u << 3,
    PROT_VERIFY_INTEGRITY   = 1u << 4,
    PROT_TAMPER_IMAGE_SIZE  = 1u << 5,
    PROT_STUB_ANTI_DEBUG    = 1u << 6,
    PROT_DIRECT_SYSCALL     = 1u << 7,
    PROT_JIT_VCODE          = 1u << 8,
    PROT_PAGE_VAULT         = 1u << 9,
    PROT_ANTI_VM            = 1u << 10,
    // Optional: leaves a minimal information-free MZ/PE shell instead of 100% zeroing
    // headers, only needed if a legacy API re-parses GetModuleHandle(NULL) after init.
    PROT_PE_SKELETON        = 1u << 11,

    PROT_DEFAULT            = PROT_ANTI_DEBUG | PROT_ANTI_DUMP | PROT_HIDE_THREAD |
                              PROT_CLEAR_HWBP | PROT_VERIFY_INTEGRITY | PROT_TAMPER_IMAGE_SIZE |
                              PROT_STUB_ANTI_DEBUG | PROT_DIRECT_SYSCALL | PROT_JIT_VCODE |
                              PROT_PAGE_VAULT | PROT_ANTI_VM
};

#pragma pack(push, 1)
struct VPackRegion {
    uint32_t rva;         // ^ field_mask(real_seed, 10)
    uint32_t size;        // ORIGINAAL plaintext size ^ field_mask(real_seed, 11)
    uint64_t key;         // region cipher key ^ splitmix64 mask (ids 13/14)
    uint64_t plain_hash;  // (blob_offset ^ m2) | ((comp_size ^ m1) << 32)
};

struct VPackHeader {
    uint32_t    magic;                  // 0x00
    uint16_t    version;                // 0x04
    uint16_t    region_count;           // 0x06
    uint32_t    flags;                  // 0x08
    uint32_t    original_entry_rva;     // 0x0C
    uint64_t    master_seed;            // 0x10 (public whitened nonce on disk; real key is split into stubs)
    uint64_t    preferred_image_base;   // 0x18
    uint32_t    orig_tls_callback_rva;  // 0x20
    uint32_t    code_reloc_count;       // 0x24
    uint32_t    orig_pdata_rva;         // 0x28
    uint32_t    orig_pdata_size;        // 0x2C
    VPackRegion regions[VPACK_MAX_REGIONS];               // 0x30 .. 0x270
    uint32_t    code_reloc_rvas[VPACK_MAX_CODE_RELOCS];   // 0x270 .. 0x8EC
    uint32_t    orig_import_rva;                          // 0x8EC
    uint32_t    vcode_rva;                                // 0x8F0
    uint32_t    vcode_size;                               // 0x8F4
    uint32_t    vinit_rva;                                // 0x8F8
    uint32_t    vinit_size;                               // 0x8FC
};
#pragma pack(pop)

static_assert(sizeof(VPackHeader) == 0x900, "VPackHeader must be exactly 0x900 bytes");

} // namespace vpack
