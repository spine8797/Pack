#pragma once

#include "vpack/config.h"
#include <cstdint>
#include <cstddef>
#include <string>
#include <array>

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

uint64_t fnv1a_64(const void* data, size_t size) noexcept;
uint64_t fnv1a_64_ci(const char* str) noexcept;

void rolling_encrypt(uint8_t* buffer, size_t size, uint64_t key) noexcept;
void rolling_decrypt(uint8_t* buffer, size_t size, uint64_t key) noexcept;

void chacha20_xor(uint8_t* data, size_t size, const uint8_t key[32], const uint8_t nonce[12], uint32_t counter = 1) noexcept;

void xtea_encrypt(uint32_t v[2], const uint32_t key[4], uint32_t rounds = 32) noexcept;
void xtea_decrypt(uint32_t v[2], const uint32_t key[4], uint32_t rounds = 32) noexcept;

template <size_t N, uint64_t Key>
class ObfuscatedString {
public:
    constexpr ObfuscatedString(const char (&str)[N]) noexcept : encrypted_{} {
        uint64_t state = Key ^ 0xA5A5F0F05A5A0F0FULL;
        for (size_t i = 0; i < N; ++i) {
            state ^= (state << 13);
            state ^= (state >> 7);
            state ^= (state << 17);
            encrypted_[i] = static_cast<uint8_t>(str[i]) ^ static_cast<uint8_t>((state >> ((i & 7) * 8)) & 0xFF);
        }
    }

    std::string decrypt() const {
        std::string out(N - 1, '\0');
        uint64_t state = Key ^ 0xA5A5F0F05A5A0F0FULL;
        for (size_t i = 0; i < N - 1; ++i) {
            state ^= (state << 13);
            state ^= (state >> 7);
            state ^= (state << 17);
            out[i] = static_cast<char>(encrypted_[i] ^ static_cast<uint8_t>((state >> ((i & 7) * 8)) & 0xFF));
        }
        return out;
    }

    const uint8_t* raw() const noexcept { return encrypted_.data(); }

private:
    std::array<uint8_t, N> encrypted_;
};

} // namespace vpack::crypto

#define VPACK_HASH_CI(s) (::vpack::crypto::fnv1a_64_ci_constexpr(s))

#define VPACK_STR(s) \
    ([]() -> std::string { \
        constexpr uint64_t kSeed = ::vpack::crypto::fnv1a_64_constexpr(__FILE__ __TIME__, sizeof(__FILE__ __TIME__) - 1) ^ static_cast<uint64_t>(__LINE__ * 0x9E3779B97F4A7C15ULL); \
        static constexpr ::vpack::crypto::ObfuscatedString<sizeof(s), kSeed> kObf(s); \
        return kObf.decrypt(); \
    }())
