#include "vpack/crypto.h"
#include <cstring>

namespace vpack::crypto {

namespace {

VPACK_FORCEINLINE uint32_t rotl32(uint32_t x, int n) noexcept {
    return (x << n) | (x >> (32 - n));
}

VPACK_FORCEINLINE uint64_t rotl64(uint64_t x, int n) noexcept {
    return (x << n) | (x >> (64 - n));
}

VPACK_FORCEINLINE void chacha_quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) noexcept {
    a += b; d ^= a; d = rotl32(d, 16);
    c += d; b ^= c; b = rotl32(b, 12);
    a += b; d ^= a; d = rotl32(d, 8);
    c += d; b ^= c; b = rotl32(b, 7);
}

} // namespace

uint64_t fnv1a_64(const void* data, size_t size) noexcept {
    const auto* bytes = static_cast<const uint8_t*>(data);
    uint64_t hash = 0xCBF29CE484222325ULL;
    for (size_t i = 0; i < size; ++i) {
        hash ^= bytes[i];
        hash *= 0x100000001B3ULL;
    }
    return hash;
}

uint64_t fnv1a_64_ci(const char* str) noexcept {
    if (!str) return 0;
    return fnv1a_64_ci_constexpr(str);
}

void rolling_encrypt(uint8_t* buffer, size_t size, uint64_t key) noexcept {
    uint64_t state = key ^ 0x7361626C655F766DULL;
    for (size_t i = 0; i < size; ++i) {
        state = rotl64(state, 13) + 0x9E3779B97F4A7C15ULL;
        uint8_t kbyte = static_cast<uint8_t>((state ^ (state >> 29)) & 0xFF);
        uint8_t plain = buffer[i];
        uint8_t enc   = static_cast<uint8_t>(((plain ^ kbyte) + static_cast<uint8_t>(i & 0xFF)) & 0xFF);
        buffer[i]     = enc;
        state ^= static_cast<uint64_t>(plain) * 0xBF58476D1CE4E5B9ULL;
    }
}

void rolling_decrypt(uint8_t* buffer, size_t size, uint64_t key) noexcept {
    uint64_t state = key ^ 0x7361626C655F766DULL;
    for (size_t i = 0; i < size; ++i) {
        state = rotl64(state, 13) + 0x9E3779B97F4A7C15ULL;
        uint8_t kbyte = static_cast<uint8_t>((state ^ (state >> 29)) & 0xFF);
        uint8_t enc   = buffer[i];
        uint8_t plain = static_cast<uint8_t>(((enc - static_cast<uint8_t>(i & 0xFF)) & 0xFF) ^ kbyte);
        buffer[i]     = plain;
        state ^= static_cast<uint64_t>(plain) * 0xBF58476D1CE4E5B9ULL;
    }
}

void chacha20_xor(uint8_t* data, size_t size, const uint8_t key[32], const uint8_t nonce[12], uint32_t counter) noexcept {
    uint32_t state[16];
    state[0] = 0x61707865;
    state[1] = 0x3320646E;
    state[2] = 0x79622D32;
    state[3] = 0x6B206574;

    std::memcpy(&state[4], key, 32);
    state[12] = counter;
    std::memcpy(&state[13], nonce, 12);

    uint32_t working[16];
    uint8_t  block[64];

    size_t offset = 0;
    while (offset < size) {
        std::memcpy(working, state, sizeof(state));
        for (int i = 0; i < 10; ++i) {
            chacha_quarter_round(working[0], working[4], working[8],  working[12]);
            chacha_quarter_round(working[1], working[5], working[9],  working[13]);
            chacha_quarter_round(working[2], working[6], working[10], working[14]);
            chacha_quarter_round(working[3], working[7], working[11], working[15]);
            chacha_quarter_round(working[0], working[5], working[10], working[15]);
            chacha_quarter_round(working[1], working[6], working[11], working[12]);
            chacha_quarter_round(working[2], working[7], working[8],  working[13]);
            chacha_quarter_round(working[3], working[4], working[9],  working[14]);
        }
        for (int i = 0; i < 16; ++i) {
            working[i] += state[i];
        }
        std::memcpy(block, working, 64);

        size_t chunk = (size - offset < 64) ? (size - offset) : 64;
        for (size_t i = 0; i < chunk; ++i) {
            data[offset + i] ^= block[i];
        }
        offset += chunk;
        state[12]++;
    }
}

void xtea_encrypt(uint32_t v[2], const uint32_t key[4], uint32_t rounds) noexcept {
    uint32_t v0 = v[0], v1 = v[1], sum = 0;
    constexpr uint32_t delta = 0x9E3779B9u;
    for (uint32_t i = 0; i < rounds; ++i) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
    }
    v[0] = v0;
    v[1] = v1;
}

void xtea_decrypt(uint32_t v[2], const uint32_t key[4], uint32_t rounds) noexcept {
    constexpr uint32_t delta = 0x9E3779B9u;
    uint32_t v0 = v[0], v1 = v[1], sum = delta * rounds;
    for (uint32_t i = 0; i < rounds; ++i) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
        sum -= delta;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
    }
    v[0] = v0;
    v[1] = v1;
}

} // namespace vpack::crypto
