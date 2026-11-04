#pragma once

#include "vpack/config.h"
#include <cstdint>
#include <cstddef>
#include <string>
#include <array>
#include <ostream>

namespace vpack::crypto {

constexpr uint64_t fnv1a_64_constexpr(const char* str, size_t len) noexcept {
    uint64_t hash = 0xCBF29CE484222325ULL;
    for (size_t i = 0; i < len; ++i) {
        hash ^= static_cast<uint8_t>(str[i]);
        hash *= 0x100000001B3ULL;
    }
    return hash;
}

constexpr uint64_t fnv1a_64_ci_constexpr(const char* str) noexcept {
    uint64_t hash = 0xCBF29CE484222325ULL;
    while (*str) {
        char c = *str++;
        if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c + ('a' - 'A'));
        }
        hash ^= static_cast<uint8_t>(c);
        hash *= 0x100000001B3ULL;
    }
    return hash;
}

// ============================================================================
// Non-Linear Mixed Boolean-Arithmetic (MBA) & Galois Field GF(2^64) Primitives
// Resistant to linear MBA simplification (QSynth/GAMBA) and SMT solvers (Z3)
// ============================================================================

// Carry-less polynomial multiplication in GF(2^64) modulo x^64 + x^4 + x^3 + x + 1 (0x1B)
constexpr uint64_t gf2_64_mul(uint64_t a, uint64_t b) noexcept {
    uint64_t result = 0;
    for (int i = 0; i < 64; ++i) {
        uint64_t mask = static_cast<uint64_t>(-static_cast<int64_t>(b & 1ULL));
        result ^= (a & mask);
        uint64_t hi = static_cast<uint64_t>(-static_cast<int64_t>((a >> 63) & 1ULL));
        a = (a << 1) ^ (0x1BULL & hi);
        b >>= 1;
    }
    return result;
}

// Non-linear MBA addition: identically equals (x + y) mod 2^64 for all x, y
constexpr VPACK_FORCEINLINE uint64_t mba_add(uint64_t x, uint64_t y) noexcept {
    const uint64_t s1 = (x ^ y) + ((x & y) << 1);
    const uint64_t s2 = (x | y) + (x & y);
    const uint64_t nl_sel = ((x * 0x9E3779B97F4A7C15ULL) ^ (y | 1ULL));
    return (s1 & nl_sel) | (s2 & ~nl_sel);
}

// Non-linear MBA subtraction: identically equals (x - y) mod 2^64 for all x, y
constexpr VPACK_FORCEINLINE uint64_t mba_sub(uint64_t x, uint64_t y) noexcept {
    const uint64_t d1 = ((x ^ ~y) + ((x & ~y) << 1)) + 1ULL;
    const uint64_t d2 = (x & ~y) - (~x & y);
    const uint64_t nl_sel = ((x ^ 0xBF58476D1CE4E5B9ULL) * (y | 3ULL));
    return (d1 & nl_sel) | (d2 & ~nl_sel);
}

// Non-linear MBA XOR: identically equals (x ^ y) for all x, y
constexpr VPACK_FORCEINLINE uint64_t mba_xor(uint64_t x, uint64_t y) noexcept {
    const uint64_t x1 = (x | y) - (x & y);
    const uint64_t x2 = (x + y) - ((x & y) << 1);
    const uint64_t nl_sel = ((x + 0x94D049BB133111EBULL) * (y ^ 0x5341424C45ULL));
    return (x1 & nl_sel) | (x2 & ~nl_sel);
}

// Bijective degree-3 Hensel permutation polynomial over Z_{2^64}:
// P(x) = 4*x^3 + 2*x^2 + (2k+1)*x + c (mod 2^64) is strictly bijective for all k.
constexpr VPACK_FORCEINLINE uint64_t poly_permute_64(uint64_t x, uint64_t key) noexcept {
    const uint64_t x2  = x * x;
    const uint64_t x3  = x2 * x;
    const uint64_t odd = (key << 1) | 1ULL;
    const uint64_t t   = mba_add((x3 << 2) + (x2 << 1), x * odd);
    return mba_xor(t, key ^ 0x7361626C655F766DULL);
}

// Hybrid GF(2^64) + Z_{2^64} Polynomial Stream Byte (used for Synthesize & Wipe strings and VM)
constexpr VPACK_FORCEINLINE uint8_t poly_stream_byte(uint64_t seed, size_t idx) noexcept {
    const uint64_t pos = static_cast<uint64_t>(idx) * 0x9E3779B97F4A7C15ULL;
    const uint64_t gf  = gf2_64_mul(seed ^ pos, 0xBF58476D1CE4E5B9ULL ^ (static_cast<uint64_t>(idx) | 1ULL));
    const uint64_t p   = poly_permute_64(gf ^ pos, seed);
    return static_cast<uint8_t>((p ^ (p >> 32) ^ (p >> 19)) & 0xFFu);
}

// Cryptographic Opaque Predicates (Hensel 2-adic residue + Mersenne Prime 8191 QNR invariant)
VPACK_FORCEINLINE bool opaque_true(uint64_t runtime_entropy) noexcept {
    volatile uint64_t v = runtime_entropy ^ 0x9E3779B97F4A7C15ULL;
    const uint64_t x    = v;
    const uint64_t odd  = (x << 1) | 1ULL;
    const uint64_t sq   = odd * odd;
    // mod 8191 (Mersenne prime 2^13 - 1 === 3 mod 4): -1 is a quadratic non-residue
    const uint64_t r    = (sq ^ x) % 8191ULL;
    const uint64_t qnr  = (r * r + 1ULL) % 8191ULL;
    return ((sq & 7ULL) == 1ULL) && (qnr != 0ULL);
}

VPACK_FORCEINLINE bool opaque_false(uint64_t runtime_entropy) noexcept {
    return !opaque_true(runtime_entropy);
}

uint64_t fnv1a_64(const void* data, size_t size) noexcept;
uint64_t fnv1a_64_ci(const char* str) noexcept;

void rolling_encrypt(uint8_t* buffer, size_t size, uint64_t key) noexcept;
void rolling_decrypt(uint8_t* buffer, size_t size, uint64_t key) noexcept;

void chacha20_xor(uint8_t* data, size_t size, const uint8_t key[32], const uint8_t nonce[12], uint32_t counter = 1) noexcept;

void xtea_encrypt(uint32_t v[2], const uint32_t key[4], uint32_t rounds = 32) noexcept;
void xtea_decrypt(uint32_t v[2], const uint32_t key[4], uint32_t rounds = 32) noexcept;

// Volatile memory scrubber: overwrites buffer with pseudo-random noise and then zeroes
void secure_wipe(void* ptr, size_t size, uint64_t noise_seed = 0x5A5AA5A5F0F00F0FULL) noexcept;

// ============================================================================
// Synthesize & Wipe String (Section II.2.3)
// Synthesizes string on demand via GF(2^64)/MBA polynomial stream and scrubs
// memory with random bytes + zeroes immediately when the expression ends.
// ============================================================================
class WipedString {
public:
    explicit WipedString(std::string&& s, uint64_t wipe_seed) noexcept
        : buf_(std::move(s)), seed_(wipe_seed) {}

    WipedString(const WipedString& other)
        : buf_(other.buf_), seed_(other.seed_ ^ 0x9E3779B97F4A7C15ULL) {}

    WipedString(WipedString&& other) noexcept
        : buf_(std::move(other.buf_)), seed_(other.seed_) {}

    WipedString& operator=(const WipedString& other) {
        if (this != &other) {
            scrub();
            buf_  = other.buf_;
            seed_ = other.seed_;
        }
        return *this;
    }

    WipedString& operator=(WipedString&& other) noexcept {
        if (this != &other) {
            scrub();
            buf_  = std::move(other.buf_);
            seed_ = other.seed_;
        }
        return *this;
    }

    ~WipedString() noexcept {
        scrub();
    }

    const char* c_str() const noexcept { return buf_.c_str(); }
    const char* data() const noexcept { return buf_.data(); }
    size_t      size() const noexcept { return buf_.size(); }
    bool        empty() const noexcept { return buf_.empty(); }

    operator const std::string&() const noexcept { return buf_; }

    friend std::ostream& operator<<(std::ostream& os, const WipedString& ws) {
        return os.write(ws.buf_.data(), static_cast<std::streamsize>(ws.buf_.size()));
    }

private:
    void scrub() noexcept {
        if (!buf_.empty()) {
            secure_wipe(&buf_[0], buf_.size(), seed_);
            buf_.clear();
        }
    }

    std::string buf_;
    uint64_t    seed_;
};

template <size_t N, uint64_t Key>
class ObfuscatedString {
public:
    constexpr ObfuscatedString(const char (&str)[N]) noexcept : encrypted_{} {
        uint64_t state = Key ^ 0xA5A5F0F05A5A0F0FULL;
        for (size_t i = 0; i < N; ++i) {
            state ^= (state << 13);
            state ^= (state >> 7);
            state ^= (state << 17);
            uint8_t stream = static_cast<uint8_t>((state >> ((i & 7) * 8)) & 0xFFu) ^
                             poly_stream_byte(Key, i);
            encrypted_[i] = static_cast<uint8_t>(str[i]) ^ stream;
        }
    }

    WipedString decrypt() const {
        std::string out(N - 1, '\0');
        uint64_t state = Key ^ 0xA5A5F0F05A5A0F0FULL;
        for (size_t i = 0; i < N - 1; ++i) {
            state ^= (state << 13);
            state ^= (state >> 7);
            state ^= (state << 17);
            uint8_t stream = static_cast<uint8_t>((state >> ((i & 7) * 8)) & 0xFFu) ^
                             poly_stream_byte(Key, i);
            out[i] = static_cast<char>(encrypted_[i] ^ stream);
        }
        return WipedString(std::move(out), state ^ Key);
    }

    const uint8_t* raw() const noexcept { return encrypted_.data(); }

private:
    std::array<uint8_t, N> encrypted_;
};

} // namespace vpack::crypto

#define VPACK_HASH_CI(s) (::vpack::crypto::fnv1a_64_ci_constexpr(s))

#define VPACK_STR(s) \
    ([]() -> ::vpack::crypto::WipedString { \
        constexpr uint64_t kSeed = ::vpack::crypto::fnv1a_64_constexpr(__FILE__ __TIME__, sizeof(__FILE__ __TIME__) - 1) ^ static_cast<uint64_t>(__LINE__ * 0x9E3779B97F4A7C15ULL); \
        static constexpr ::vpack::crypto::ObfuscatedString<sizeof(s), kSeed> kObf(s); \
        return kObf.decrypt(); \
    }())
