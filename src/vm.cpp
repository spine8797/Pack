#include "vpack/vm.h"
#include "vpack/crypto.h"
#include "vpack/anti_debug.h"
#include "vpack/anti_dump.h"
#include <intrin.h>
#include <cstring>
#include <cstdlib>

namespace vpack::vm {

namespace {

// Position-independent ephemeral stream byte so random-access jumps (JMP/JZ/JNZ)
// strip the per-run RDTSC layer in registers while the instruction-chained rolling
// key decrypts 1 byte at a time without ever holding plaintext bytecode in RAM.
VPACK_FORCEINLINE uint8_t ephemeral_stream_byte(uint64_t key, size_t idx) noexcept {
    uint64_t x = key ^ (static_cast<uint64_t>(idx) * 0x9E3779B97F4A7C15ULL);
    x ^= (x >> 30);
    x *= 0xBF58476D1CE4E5B9ULL;
    x ^= (x >> 27);
    return static_cast<uint8_t>((x ^ (x >> 31)) & 0xFFu);
}

VPACK_FORCEINLINE void update_cmp_flags(VmContext& ctx, uint64_t lhs, uint64_t rhs) noexcept {
    uint64_t res = crypto::mba_sub(lhs, rhs);
    ctx.flags &= ~(FLAG_ZF | FLAG_SF | FLAG_CF | FLAG_OF);
    if (res == 0) {
        ctx.flags |= FLAG_ZF;
    }
    if ((res >> 63) & 1ULL) {
        ctx.flags |= FLAG_SF;
    }
    if (lhs < rhs) {
        ctx.flags |= FLAG_CF;
    }
    bool sign_lhs = ((lhs >> 63) & 1ULL) != 0;
    bool sign_rhs = ((rhs >> 63) & 1ULL) != 0;
    bool sign_res = ((res >> 63) & 1ULL) != 0;
    if ((sign_lhs != sign_rhs) && (sign_lhs != sign_res)) {
        ctx.flags |= FLAG_OF;
    }
}

VPACK_FORCEINLINE void update_add_flags(VmContext& ctx, uint64_t lhs, uint64_t rhs, uint64_t res) noexcept {
    ctx.flags &= ~(FLAG_ZF | FLAG_SF | FLAG_CF | FLAG_OF);
    if (res == 0) {
        ctx.flags |= FLAG_ZF;
    }
    if ((res >> 63) & 1ULL) {
        ctx.flags |= FLAG_SF;
    }
    if (res < lhs) {
        ctx.flags |= FLAG_CF;
    }
    bool sign_lhs = ((lhs >> 63) & 1ULL) != 0;
    bool sign_rhs = ((rhs >> 63) & 1ULL) != 0;
    bool sign_res = ((res >> 63) & 1ULL) != 0;
    if ((sign_lhs == sign_rhs) && (sign_lhs != sign_res)) {
        ctx.flags |= FLAG_OF;
    }
}

VPACK_FORCEINLINE void update_alu_flags(VmContext& ctx, uint64_t val) noexcept {
    ctx.flags &= ~(FLAG_ZF | FLAG_SF | FLAG_CF | FLAG_OF);
    if (val == 0) ctx.flags |= FLAG_ZF;
    if ((val >> 63) & 1ULL) ctx.flags |= FLAG_SF;
}

constexpr uintptr_t kHandlerPtrMask = static_cast<uintptr_t>(0xD6E8FEB86659FD93ULL);

struct VmExecState;
using VmHandlerFn = bool(*)(VmExecState&) noexcept;

VPACK_FORCEINLINE uintptr_t encode_handler_slot(VmHandlerFn fn, uintptr_t mask, size_t idx) noexcept {
    const uintptr_t addr = reinterpret_cast<uintptr_t>(reinterpret_cast<void*>(fn));
    const uintptr_t salt = static_cast<uintptr_t>(crypto::poly_permute_64(idx, mask));
    return static_cast<uintptr_t>(crypto::mba_xor(addr, crypto::mba_add(mask, salt)));
}

VPACK_FORCEINLINE VmHandlerFn decode_handler_slot(uintptr_t encoded, uintptr_t mask, size_t idx) noexcept {
    const uintptr_t salt = static_cast<uintptr_t>(crypto::poly_permute_64(idx, mask));
    const uintptr_t raw  = static_cast<uintptr_t>(crypto::mba_xor(encoded, crypto::mba_add(mask, salt)));
    return reinterpret_cast<VmHandlerFn>(reinterpret_cast<void*>(raw));
}

struct VmExecState {
    VmContext&                                          ctx;
    std::vector<uint8_t>&                               code;
    size_t                                              code_size;
    uint64_t                                            seed;
    uint64_t                                            ephemeral_key;
    uintptr_t                                           runtime_ptr_mask;
    const PolymorphicOpcodeTable&                       op_table;
    const std::array<uintptr_t, OP_MAX_COUNT>&          encrypted_handlers;
    const std::unordered_map<uint16_t, NativeCallback>& native_table;

    // Reads 1 byte by stripping the ephemeral RDTSC layer AND stepping the
    // instruction-chained rolling state in CPU registers (never in RAM).
    VPACK_FORCEINLINE bool read_u8(uint8_t& out) noexcept {
        if (ctx.ip >= code_size) return false;
        const size_t idx    = ctx.ip++;
        const uint8_t cbyte = static_cast<uint8_t>(code[idx] ^ ephemeral_stream_byte(ephemeral_key, idx));
        const uint8_t kbyte = rolling_stream_byte(ctx.rolling_state, idx, seed);
        const uint8_t plain = static_cast<uint8_t>(cbyte ^ kbyte);
        ctx.rolling_state   = step_rolling_state(ctx.rolling_state, plain, idx, seed);
        out                 = plain;
        return true;
    }

    VPACK_FORCEINLINE bool read_u16(uint16_t& out) noexcept {
        uint8_t b0 = 0, b1 = 0;
        if (!read_u8(b0) || !read_u8(b1)) return false;
        out = static_cast<uint16_t>(b0) | (static_cast<uint16_t>(b1) << 8);
        return true;
    }

    VPACK_FORCEINLINE bool read_u32(uint32_t& out) noexcept {
        out = 0;
        for (int i = 0; i < 4; ++i) {
            uint8_t b = 0;
            if (!read_u8(b)) return false;
            out |= static_cast<uint32_t>(b) << (i * 8);
        }
        return true;
    }

    VPACK_FORCEINLINE bool read_u64(uint64_t& out) noexcept {
        out = 0;
        for (int i = 0; i < 8; ++i) {
            uint8_t b = 0;
            if (!read_u8(b)) return false;
            out |= static_cast<uint64_t>(b) << (i * 8);
        }
        return true;
    }
};

// Direct Threaded + Entangled MBA Dispatch: each handler chains directly to the next handler
VPACK_CODE bool dispatch_next(VmExecState& s) noexcept {
    if (s.ctx.halted || s.ctx.ip >= s.code_size) {
        return s.ctx.halted && !s.ctx.tampered;
    }

    uint8_t phys_op = 0;
    if (!s.read_u8(phys_op)) {
        return false;
    }

    const uint8_t logical_op = s.op_table.physical_to_logical[phys_op];
    if (logical_op >= OP_MAX_COUNT || crypto::opaque_false(s.ctx.rolling_state ^ phys_op)) {
        s.ctx.tampered = true;
        s.ctx.halted = true;
        return false;
    }

    const auto next_handler = decode_handler_slot(
        s.encrypted_handlers[logical_op],
        s.runtime_ptr_mask,
        logical_op
    );
    return next_handler(s);
}

VPACK_CODE bool h_nop(VmExecState& s) noexcept {
    return dispatch_next(s);
}

VPACK_CODE bool h_mov_imm(VmExecState& s) noexcept {
    uint8_t dst = 0; uint64_t imm = 0;
    if (!s.read_u8(dst) || !s.read_u64(imm) || dst >= REG_COUNT) return false;
    s.ctx.vreg(dst) = imm;
    return dispatch_next(s);
}

VPACK_CODE bool h_mov_reg(VmExecState& s) noexcept {
    uint8_t dst = 0, src = 0;
    if (!s.read_u8(dst) || !s.read_u8(src) || dst >= REG_COUNT || src >= REG_COUNT) return false;
    s.ctx.vreg(dst) = s.ctx.vreg(src);
    return dispatch_next(s);
}

VPACK_CODE bool h_add_reg(VmExecState& s) noexcept {
    uint8_t dst = 0, src = 0;
    if (!s.read_u8(dst) || !s.read_u8(src) || dst >= REG_COUNT || src >= REG_COUNT) return false;
    const uint64_t lhs = s.ctx.vreg(dst);
    const uint64_t rhs = s.ctx.vreg(src);
    const uint64_t res = crypto::mba_add(lhs, rhs);
    s.ctx.vreg(dst)    = res;
    update_add_flags(s.ctx, lhs, rhs, res);
    return dispatch_next(s);
}

VPACK_CODE bool h_add_imm(VmExecState& s) noexcept {
    uint8_t dst = 0; uint64_t imm = 0;
    if (!s.read_u8(dst) || !s.read_u64(imm) || dst >= REG_COUNT) return false;
    const uint64_t lhs = s.ctx.vreg(dst);
    const uint64_t res = crypto::mba_add(lhs, imm);
    s.ctx.vreg(dst)    = res;
    update_add_flags(s.ctx, lhs, imm, res);
    return dispatch_next(s);
}

VPACK_CODE bool h_sub_reg(VmExecState& s) noexcept {
    uint8_t dst = 0, src = 0;
    if (!s.read_u8(dst) || !s.read_u8(src) || dst >= REG_COUNT || src >= REG_COUNT) return false;
    const uint64_t lhs = s.ctx.vreg(dst);
    const uint64_t rhs = s.ctx.vreg(src);
    update_cmp_flags(s.ctx, lhs, rhs);
    s.ctx.vreg(dst) = crypto::mba_sub(lhs, rhs);
    return dispatch_next(s);
}

VPACK_CODE bool h_sub_imm(VmExecState& s) noexcept {
    uint8_t dst = 0; uint64_t imm = 0;
    if (!s.read_u8(dst) || !s.read_u64(imm) || dst >= REG_COUNT) return false;
    const uint64_t lhs = s.ctx.vreg(dst);
    update_cmp_flags(s.ctx, lhs, imm);
    s.ctx.vreg(dst) = crypto::mba_sub(lhs, imm);
    return dispatch_next(s);
}

VPACK_CODE bool h_imul_reg(VmExecState& s) noexcept {
    uint8_t dst = 0, src = 0;
    if (!s.read_u8(dst) || !s.read_u8(src) || dst >= REG_COUNT || src >= REG_COUNT) return false;
    s.ctx.vreg(dst) *= s.ctx.vreg(src);
    update_alu_flags(s.ctx, s.ctx.vreg(dst));
    return dispatch_next(s);
}

VPACK_CODE bool h_xor_reg(VmExecState& s) noexcept {
    uint8_t dst = 0, src = 0;
    if (!s.read_u8(dst) || !s.read_u8(src) || dst >= REG_COUNT || src >= REG_COUNT) return false;
    s.ctx.vreg(dst) = crypto::mba_xor(s.ctx.vreg(dst), s.ctx.vreg(src));
    update_alu_flags(s.ctx, s.ctx.vreg(dst));
    return dispatch_next(s);
}

VPACK_CODE bool h_xor_imm(VmExecState& s) noexcept {
    uint8_t dst = 0; uint64_t imm = 0;
    if (!s.read_u8(dst) || !s.read_u64(imm) || dst >= REG_COUNT) return false;
    s.ctx.vreg(dst) = crypto::mba_xor(s.ctx.vreg(dst), imm);
    update_alu_flags(s.ctx, s.ctx.vreg(dst));
    return dispatch_next(s);
}

VPACK_CODE bool h_and_reg(VmExecState& s) noexcept {
    uint8_t dst = 0, src = 0;
    if (!s.read_u8(dst) || !s.read_u8(src) || dst >= REG_COUNT || src >= REG_COUNT) return false;
    s.ctx.vreg(dst) &= s.ctx.vreg(src);
    update_alu_flags(s.ctx, s.ctx.vreg(dst));
    return dispatch_next(s);
}

VPACK_CODE bool h_or_reg(VmExecState& s) noexcept {
    uint8_t dst = 0, src = 0;
    if (!s.read_u8(dst) || !s.read_u8(src) || dst >= REG_COUNT || src >= REG_COUNT) return false;
    s.ctx.vreg(dst) |= s.ctx.vreg(src);
    update_alu_flags(s.ctx, s.ctx.vreg(dst));
    return dispatch_next(s);
}

VPACK_CODE bool h_shl_imm(VmExecState& s) noexcept {
    uint8_t dst = 0, shift = 0;
    if (!s.read_u8(dst) || !s.read_u8(shift) || dst >= REG_COUNT) return false;
    s.ctx.vreg(dst) <<= (shift & 63);
    update_alu_flags(s.ctx, s.ctx.vreg(dst));
    return dispatch_next(s);
}

VPACK_CODE bool h_shr_imm(VmExecState& s) noexcept {
    uint8_t dst = 0, shift = 0;
    if (!s.read_u8(dst) || !s.read_u8(shift) || dst >= REG_COUNT) return false;
    s.ctx.vreg(dst) >>= (shift & 63);
    update_alu_flags(s.ctx, s.ctx.vreg(dst));
    return dispatch_next(s);
}

VPACK_CODE bool h_rol_imm(VmExecState& s) noexcept {
    uint8_t dst = 0, shift = 0;
    if (!s.read_u8(dst) || !s.read_u8(shift) || dst >= REG_COUNT) return false;
    uint8_t sh = shift & 63;
    if (sh != 0) s.ctx.vreg(dst) = (s.ctx.vreg(dst) << sh) | (s.ctx.vreg(dst) >> (64 - sh));
    update_alu_flags(s.ctx, s.ctx.vreg(dst));
    return dispatch_next(s);
}

VPACK_CODE bool h_ror_imm(VmExecState& s) noexcept {
    uint8_t dst = 0, shift = 0;
    if (!s.read_u8(dst) || !s.read_u8(shift) || dst >= REG_COUNT) return false;
    uint8_t sh = shift & 63;
    if (sh != 0) s.ctx.vreg(dst) = (s.ctx.vreg(dst) >> sh) | (s.ctx.vreg(dst) << (64 - sh));
    update_alu_flags(s.ctx, s.ctx.vreg(dst));
    return dispatch_next(s);
}

VPACK_CODE bool h_not_reg(VmExecState& s) noexcept {
    uint8_t dst = 0;
    if (!s.read_u8(dst) || dst >= REG_COUNT) return false;
    s.ctx.vreg(dst) = ~s.ctx.vreg(dst);
    update_alu_flags(s.ctx, s.ctx.vreg(dst));
    return dispatch_next(s);
}

VPACK_CODE bool h_neg_reg(VmExecState& s) noexcept {
    uint8_t dst = 0;
    if (!s.read_u8(dst) || dst >= REG_COUNT) return false;
    const uint64_t rhs = s.ctx.vreg(dst);
    update_cmp_flags(s.ctx, 0ULL, rhs);
    s.ctx.vreg(dst) = static_cast<uint64_t>(-static_cast<int64_t>(rhs));
    return dispatch_next(s);
}

VPACK_CODE bool h_cmp_reg(VmExecState& s) noexcept {
    uint8_t lhs = 0, rhs = 0;
    if (!s.read_u8(lhs) || !s.read_u8(rhs) || lhs >= REG_COUNT || rhs >= REG_COUNT) return false;
    update_cmp_flags(s.ctx, s.ctx.vreg(lhs), s.ctx.vreg(rhs));
    return dispatch_next(s);
}

VPACK_CODE bool h_cmp_imm(VmExecState& s) noexcept {
    uint8_t lhs = 0; uint64_t imm = 0;
    if (!s.read_u8(lhs) || !s.read_u64(imm) || lhs >= REG_COUNT) return false;
    update_cmp_flags(s.ctx, s.ctx.vreg(lhs), imm);
    return dispatch_next(s);
}

VPACK_CODE bool h_jmp(VmExecState& s) noexcept {
    uint32_t target = 0;
    if (!s.read_u32(target) || target >= s.code_size) return false;
    s.ctx.ip            = target;
    s.ctx.rolling_state = sync_rolling_state(s.seed, target) ^ s.ctx.env_poison;
    return dispatch_next(s);
}

VPACK_CODE bool h_jz(VmExecState& s) noexcept {
    uint32_t target = 0;
    if (!s.read_u32(target) || target >= s.code_size) return false;
    if (s.ctx.flags & FLAG_ZF) {
        s.ctx.ip            = target;
        s.ctx.rolling_state = sync_rolling_state(s.seed, target) ^ s.ctx.env_poison;
    }
    return dispatch_next(s);
}

VPACK_CODE bool h_jnz(VmExecState& s) noexcept {
    uint32_t target = 0;
    if (!s.read_u32(target) || target >= s.code_size) return false;
    if (!(s.ctx.flags & FLAG_ZF)) {
        s.ctx.ip            = target;
        s.ctx.rolling_state = sync_rolling_state(s.seed, target) ^ s.ctx.env_poison;
    }
    return dispatch_next(s);
}

VPACK_CODE bool h_jg(VmExecState& s) noexcept {
    uint32_t target = 0;
    if (!s.read_u32(target) || target >= s.code_size) return false;
    bool zf = (s.ctx.flags & FLAG_ZF) != 0;
    bool sf = (s.ctx.flags & FLAG_SF) != 0;
    bool of = (s.ctx.flags & FLAG_OF) != 0;
    if (!zf && (sf == of)) {
        s.ctx.ip            = target;
        s.ctx.rolling_state = sync_rolling_state(s.seed, target) ^ s.ctx.env_poison;
    }
    return dispatch_next(s);
}

VPACK_CODE bool h_jl(VmExecState& s) noexcept {
    uint32_t target = 0;
    if (!s.read_u32(target) || target >= s.code_size) return false;
    bool sf = (s.ctx.flags & FLAG_SF) != 0;
    bool of = (s.ctx.flags & FLAG_OF) != 0;
    if (sf != of) {
        s.ctx.ip            = target;
        s.ctx.rolling_state = sync_rolling_state(s.seed, target) ^ s.ctx.env_poison;
    }
    return dispatch_next(s);
}

// Bipartite Encrypted Stack Push: stack values are never plaintext in RAM
VPACK_CODE bool h_push_reg(VmExecState& s) noexcept {
    uint8_t src = 0;
    if (!s.read_u8(src) || src >= REG_COUNT) return false;
    const size_t sp     = s.ctx.stack.size();
    const uint64_t mask = crypto::poly_permute_64(s.ctx.stack_key, sp);
    s.ctx.stack.push_back(crypto::mba_xor(s.ctx.vreg(src), mask));
    return dispatch_next(s);
}

VPACK_CODE bool h_pop_reg(VmExecState& s) noexcept {
    uint8_t dst = 0;
    if (!s.read_u8(dst) || dst >= REG_COUNT || s.ctx.stack.empty()) return false;
    const size_t sp     = s.ctx.stack.size() - 1;
    const uint64_t mask = crypto::poly_permute_64(s.ctx.stack_key, sp);
    s.ctx.vreg(dst)     = crypto::mba_xor(s.ctx.stack.back(), mask);
    s.ctx.stack.pop_back();
    return dispatch_next(s);
}

VPACK_CODE bool h_load64(VmExecState& s) noexcept {
    uint8_t dst = 0, addr_reg = 0;
    if (!s.read_u8(dst) || !s.read_u8(addr_reg) || dst >= REG_COUNT || addr_reg >= REG_COUNT) return false;
    const auto* ptr = reinterpret_cast<const uint64_t*>(s.ctx.vreg(addr_reg));
    if (!ptr) return false;
    std::memcpy(&s.ctx.vreg(dst), ptr, sizeof(uint64_t));
    return dispatch_next(s);
}

VPACK_CODE bool h_store64(VmExecState& s) noexcept {
    uint8_t addr_reg = 0, src = 0;
    if (!s.read_u8(addr_reg) || !s.read_u8(src) || addr_reg >= REG_COUNT || src >= REG_COUNT) return false;
    auto* ptr = reinterpret_cast<uint64_t*>(s.ctx.vreg(addr_reg));
    if (!ptr) return false;
    std::memcpy(ptr, &s.ctx.vreg(src), sizeof(uint64_t));
    return dispatch_next(s);
}

VPACK_CODE bool h_call_native(VmExecState& s) noexcept {
    uint16_t slot = 0; uint8_t dst_ret = 0;
    if (!s.read_u16(slot) || !s.read_u8(dst_ret) || dst_ret >= REG_COUNT) return false;
    auto it = s.native_table.find(slot);
    if (it == s.native_table.end() || !it->second) return false;
    s.ctx.vreg(dst_ret) = it->second(
        s.ctx.vreg(R0), s.ctx.vreg(R1), s.ctx.vreg(R2), s.ctx.vreg(R3)
    );
    return dispatch_next(s);
}

VPACK_CODE bool h_anti_debug_check(VmExecState& s) noexcept {
    const uint64_t live_poison = antidebug::compute_environmental_key_poison();
    s.ctx.env_poison ^= live_poison;
    if (live_poison != 0 || antidebug::check_peb_being_debugged() || antidebug::check_nt_global_flag()) {
        s.ctx.tampered = true;
        s.ctx.flags |= FLAG_TRAP;
        for (uint8_t i = 0; i < REG_COUNT; ++i) {
            s.ctx.vreg(i) = crypto::mba_xor(s.ctx.vreg(i), live_poison ^ 0xDEAD0000BAD00000ULL);
        }
    }
    return dispatch_next(s);
}

// Synchronizes rolling decryption key at basic-block label entry
VPACK_CODE bool h_sync_state(VmExecState& s) noexcept {
    s.ctx.rolling_state = sync_rolling_state(s.seed, s.ctx.ip) ^ s.ctx.env_poison;
    return dispatch_next(s);
}

VPACK_CODE bool h_mba_add(VmExecState& s) noexcept {
    uint8_t dst = 0, src = 0;
    if (!s.read_u8(dst) || !s.read_u8(src) || dst >= REG_COUNT || src >= REG_COUNT) return false;
    const uint64_t lhs = s.ctx.vreg(dst);
    const uint64_t rhs = s.ctx.vreg(src);
    const uint64_t res = crypto::mba_add(lhs, rhs);
    s.ctx.vreg(dst)    = res;
    update_add_flags(s.ctx, lhs, rhs, res);
    return dispatch_next(s);
}

VPACK_CODE bool h_mba_sub(VmExecState& s) noexcept {
    uint8_t dst = 0, src = 0;
    if (!s.read_u8(dst) || !s.read_u8(src) || dst >= REG_COUNT || src >= REG_COUNT) return false;
    const uint64_t lhs = s.ctx.vreg(dst);
    const uint64_t rhs = s.ctx.vreg(src);
    update_cmp_flags(s.ctx, lhs, rhs);
    s.ctx.vreg(dst) = crypto::mba_sub(lhs, rhs);
    return dispatch_next(s);
}

VPACK_CODE bool h_mba_xor(VmExecState& s) noexcept {
    uint8_t dst = 0, src = 0;
    if (!s.read_u8(dst) || !s.read_u8(src) || dst >= REG_COUNT || src >= REG_COUNT) return false;
    s.ctx.vreg(dst) = crypto::mba_xor(s.ctx.vreg(dst), s.ctx.vreg(src));
    update_alu_flags(s.ctx, s.ctx.vreg(dst));
    return dispatch_next(s);
}

VPACK_CODE bool h_gf2_mul(VmExecState& s) noexcept {
    uint8_t dst = 0, src = 0;
    if (!s.read_u8(dst) || !s.read_u8(src) || dst >= REG_COUNT || src >= REG_COUNT) return false;
    s.ctx.vreg(dst) = crypto::gf2_64_mul(s.ctx.vreg(dst), s.ctx.vreg(src));
    update_alu_flags(s.ctx, s.ctx.vreg(dst));
    return dispatch_next(s);
}

// Dynamically rotates the virtual-to-physical register mapping in RAM so physical
// register slots constantly change location while preserving virtual register values.
VPACK_CODE bool h_rotate_regs(VmExecState& s) noexcept {
    uint8_t step = 0;
    if (!s.read_u8(step)) return false;
    const uint8_t rot = (step & 0x0Fu) | 1u;

    std::array<uint64_t, 16> logical_snapshot{};
    for (uint8_t i = 0; i < 16; ++i) {
        logical_snapshot[i] = s.ctx.vreg(i);
    }
    for (uint8_t i = 0; i < 16; ++i) {
        s.ctx.reg_map[i] = static_cast<uint8_t>((s.ctx.reg_map[i] + rot) & 0x0Fu);
    }
    for (uint8_t i = 0; i < 16; ++i) {
        s.ctx.regs[s.ctx.reg_map[i]] = logical_snapshot[i];
    }
    crypto::secure_wipe(logical_snapshot.data(), sizeof(logical_snapshot), s.ctx.rolling_state);
    return dispatch_next(s);
}

// State-Matrix Automaton: applies an invertible 2x2 Feistel-Matrix transformation
// over (R0, R1) in GF(2^64) x Z_{2^64}
VPACK_CODE bool h_state_matrix(VmExecState& s) noexcept {
    uint8_t mkey = 0;
    if (!s.read_u8(mkey)) return false;
    const uint64_t k  = static_cast<uint64_t>(mkey) * 0x9E3779B97F4A7C15ULL;
    const uint64_t r0 = s.ctx.vreg(R0);
    const uint64_t r1 = s.ctx.vreg(R1);
    const uint64_t f0 = crypto::gf2_64_mul(r1 ^ k, 0xBF58476D1CE4E5B9ULL | 1ULL);
    const uint64_t n0 = crypto::mba_xor(r0, crypto::mba_add(f0, r1 * 0x94D049BB133111EBULL));
    const uint64_t f1 = crypto::poly_permute_64(n0, k ^ 0xE791C3A58B2D4F19ULL);
    const uint64_t n1 = crypto::mba_xor(r1, f1);
    s.ctx.vreg(R0)    = n0;
    s.ctx.vreg(R1)    = n1;
    update_alu_flags(s.ctx, n0);
    return dispatch_next(s);
}

// Branchless Environmental Key Entanglement: mixes live anti-debug/integrity poison into dst
VPACK_CODE bool h_entangle_env(VmExecState& s) noexcept {
    uint8_t dst = 0;
    if (!s.read_u8(dst) || dst >= REG_COUNT) return false;
    const uint64_t poison = antidebug::compute_environmental_key_poison() ^ s.ctx.env_poison;
    s.ctx.vreg(dst)       = crypto::mba_xor(s.ctx.vreg(dst), poison);
    return dispatch_next(s);
}

VPACK_CODE bool h_jge(VmExecState& s) noexcept {
    uint32_t target = 0;
    if (!s.read_u32(target) || target >= s.code_size) return false;
    bool sf = (s.ctx.flags & FLAG_SF) != 0;
    bool of = (s.ctx.flags & FLAG_OF) != 0;
    if (sf == of) {
        s.ctx.ip            = target;
        s.ctx.rolling_state = sync_rolling_state(s.seed, target) ^ s.ctx.env_poison;
    }
    return dispatch_next(s);
}

VPACK_CODE bool h_jle(VmExecState& s) noexcept {
    uint32_t target = 0;
    if (!s.read_u32(target) || target >= s.code_size) return false;
    bool zf = (s.ctx.flags & FLAG_ZF) != 0;
    bool sf = (s.ctx.flags & FLAG_SF) != 0;
    bool of = (s.ctx.flags & FLAG_OF) != 0;
    if (zf || (sf != of)) {
        s.ctx.ip            = target;
        s.ctx.rolling_state = sync_rolling_state(s.seed, target) ^ s.ctx.env_poison;
    }
    return dispatch_next(s);
}

VPACK_CODE bool h_ja(VmExecState& s) noexcept {
    uint32_t target = 0;
    if (!s.read_u32(target) || target >= s.code_size) return false;
    bool cf = (s.ctx.flags & FLAG_CF) != 0;
    bool zf = (s.ctx.flags & FLAG_ZF) != 0;
    if (!cf && !zf) {
        s.ctx.ip            = target;
        s.ctx.rolling_state = sync_rolling_state(s.seed, target) ^ s.ctx.env_poison;
    }
    return dispatch_next(s);
}

VPACK_CODE bool h_jb(VmExecState& s) noexcept {
    uint32_t target = 0;
    if (!s.read_u32(target) || target >= s.code_size) return false;
    if (s.ctx.flags & FLAG_CF) {
        s.ctx.ip            = target;
        s.ctx.rolling_state = sync_rolling_state(s.seed, target) ^ s.ctx.env_poison;
    }
    return dispatch_next(s);
}

VPACK_CODE bool h_jae(VmExecState& s) noexcept {
    uint32_t target = 0;
    if (!s.read_u32(target) || target >= s.code_size) return false;
    if (!(s.ctx.flags & FLAG_CF)) {
        s.ctx.ip            = target;
        s.ctx.rolling_state = sync_rolling_state(s.seed, target) ^ s.ctx.env_poison;
    }
    return dispatch_next(s);
}

VPACK_CODE bool h_jbe(VmExecState& s) noexcept {
    uint32_t target = 0;
    if (!s.read_u32(target) || target >= s.code_size) return false;
    if (s.ctx.flags & (FLAG_CF | FLAG_ZF)) {
        s.ctx.ip            = target;
        s.ctx.rolling_state = sync_rolling_state(s.seed, target) ^ s.ctx.env_poison;
    }
    return dispatch_next(s);
}

VPACK_CODE bool h_shl_reg(VmExecState& s) noexcept {
    uint8_t dst = 0, src = 0;
    if (!s.read_u8(dst) || !s.read_u8(src) || dst >= REG_COUNT || src >= REG_COUNT) return false;
    s.ctx.vreg(dst) <<= (s.ctx.vreg(src) & 63ULL);
    update_alu_flags(s.ctx, s.ctx.vreg(dst));
    return dispatch_next(s);
}

VPACK_CODE bool h_shr_reg(VmExecState& s) noexcept {
    uint8_t dst = 0, src = 0;
    if (!s.read_u8(dst) || !s.read_u8(src) || dst >= REG_COUNT || src >= REG_COUNT) return false;
    s.ctx.vreg(dst) >>= (s.ctx.vreg(src) & 63ULL);
    update_alu_flags(s.ctx, s.ctx.vreg(dst));
    return dispatch_next(s);
}

VPACK_CODE bool h_sar_imm(VmExecState& s) noexcept {
    uint8_t dst = 0, shift = 0;
    if (!s.read_u8(dst) || !s.read_u8(shift) || dst >= REG_COUNT) return false;
    s.ctx.vreg(dst) = static_cast<uint64_t>(static_cast<int64_t>(s.ctx.vreg(dst)) >> (shift & 63u));
    update_alu_flags(s.ctx, s.ctx.vreg(dst));
    return dispatch_next(s);
}

VPACK_CODE bool h_movzx32(VmExecState& s) noexcept {
    uint8_t dst = 0, src = 0;
    if (!s.read_u8(dst) || !s.read_u8(src) || dst >= REG_COUNT || src >= REG_COUNT) return false;
    s.ctx.vreg(dst) = static_cast<uint64_t>(static_cast<uint32_t>(s.ctx.vreg(src)));
    return dispatch_next(s);
}

VPACK_CODE bool h_ret(VmExecState& s) noexcept {
    s.ctx.halted = true;
    return !s.ctx.tampered;
}

VPACK_CODE bool h_load8(VmExecState& s) noexcept {
    uint8_t dst = 0, addr_reg = 0;
    if (!s.read_u8(dst) || !s.read_u8(addr_reg) || dst >= REG_COUNT || addr_reg >= REG_COUNT) return false;
    const auto* ptr = reinterpret_cast<const uint8_t*>(s.ctx.vreg(addr_reg));
    if (!ptr) return false;
    s.ctx.vreg(dst) = static_cast<uint64_t>(*ptr);
    return dispatch_next(s);
}

VPACK_CODE bool h_load16(VmExecState& s) noexcept {
    uint8_t dst = 0, addr_reg = 0;
    if (!s.read_u8(dst) || !s.read_u8(addr_reg) || dst >= REG_COUNT || addr_reg >= REG_COUNT) return false;
    const auto* ptr = reinterpret_cast<const uint16_t*>(s.ctx.vreg(addr_reg));
    if (!ptr) return false;
    uint16_t val = 0;
    std::memcpy(&val, ptr, sizeof(uint16_t));
    s.ctx.vreg(dst) = static_cast<uint64_t>(val);
    return dispatch_next(s);
}

VPACK_CODE bool h_load32(VmExecState& s) noexcept {
    uint8_t dst = 0, addr_reg = 0;
    if (!s.read_u8(dst) || !s.read_u8(addr_reg) || dst >= REG_COUNT || addr_reg >= REG_COUNT) return false;
    const auto* ptr = reinterpret_cast<const uint32_t*>(s.ctx.vreg(addr_reg));
    if (!ptr) return false;
    uint32_t val = 0;
    std::memcpy(&val, ptr, sizeof(uint32_t));
    s.ctx.vreg(dst) = static_cast<uint64_t>(val);
    return dispatch_next(s);
}

VPACK_CODE bool h_store8(VmExecState& s) noexcept {
    uint8_t addr_reg = 0, src = 0;
    if (!s.read_u8(addr_reg) || !s.read_u8(src) || addr_reg >= REG_COUNT || src >= REG_COUNT) return false;
    auto* ptr = reinterpret_cast<uint8_t*>(s.ctx.vreg(addr_reg));
    if (!ptr) return false;
    *ptr = static_cast<uint8_t>(s.ctx.vreg(src) & 0xFFu);
    return dispatch_next(s);
}

VPACK_CODE bool h_store16(VmExecState& s) noexcept {
    uint8_t addr_reg = 0, src = 0;
    if (!s.read_u8(addr_reg) || !s.read_u8(src) || addr_reg >= REG_COUNT || src >= REG_COUNT) return false;
    auto* ptr = reinterpret_cast<uint16_t*>(s.ctx.vreg(addr_reg));
    if (!ptr) return false;
    uint16_t val = static_cast<uint16_t>(s.ctx.vreg(src) & 0xFFFFu);
    std::memcpy(ptr, &val, sizeof(uint16_t));
    return dispatch_next(s);
}

VPACK_CODE bool h_store32(VmExecState& s) noexcept {
    uint8_t addr_reg = 0, src = 0;
    if (!s.read_u8(addr_reg) || !s.read_u8(src) || addr_reg >= REG_COUNT || src >= REG_COUNT) return false;
    auto* ptr = reinterpret_cast<uint32_t*>(s.ctx.vreg(addr_reg));
    if (!ptr) return false;
    uint32_t val = static_cast<uint32_t>(s.ctx.vreg(src) & 0xFFFFFFFFu);
    std::memcpy(ptr, &val, sizeof(uint32_t));
    return dispatch_next(s);
}

VPACK_CODE bool h_sar_reg(VmExecState& s) noexcept {
    uint8_t dst = 0, src = 0;
    if (!s.read_u8(dst) || !s.read_u8(src) || dst >= REG_COUNT || src >= REG_COUNT) return false;
    const uint8_t sh = static_cast<uint8_t>(s.ctx.vreg(src) & 63ULL);
    s.ctx.vreg(dst) = static_cast<uint64_t>(static_cast<int64_t>(s.ctx.vreg(dst)) >> sh);
    update_alu_flags(s.ctx, s.ctx.vreg(dst));
    return dispatch_next(s);
}

VPACK_CODE bool h_js(VmExecState& s) noexcept {
    uint32_t target = 0;
    if (!s.read_u32(target) || target >= s.code_size) return false;
    if (s.ctx.flags & FLAG_SF) {
        s.ctx.ip            = target;
        s.ctx.rolling_state = sync_rolling_state(s.seed, target) ^ s.ctx.env_poison;
    }
    return dispatch_next(s);
}

VPACK_CODE bool h_jns(VmExecState& s) noexcept {
    uint32_t target = 0;
    if (!s.read_u32(target) || target >= s.code_size) return false;
    if (!(s.ctx.flags & FLAG_SF)) {
        s.ctx.ip            = target;
        s.ctx.rolling_state = sync_rolling_state(s.seed, target) ^ s.ctx.env_poison;
    }
    return dispatch_next(s);
}

VPACK_CODE bool h_jo(VmExecState& s) noexcept {
    uint32_t target = 0;
    if (!s.read_u32(target) || target >= s.code_size) return false;
    if (s.ctx.flags & FLAG_OF) {
        s.ctx.ip            = target;
        s.ctx.rolling_state = sync_rolling_state(s.seed, target) ^ s.ctx.env_poison;
    }
    return dispatch_next(s);
}

VPACK_CODE bool h_jno(VmExecState& s) noexcept {
    uint32_t target = 0;
    if (!s.read_u32(target) || target >= s.code_size) return false;
    if (!(s.ctx.flags & FLAG_OF)) {
        s.ctx.ip            = target;
        s.ctx.rolling_state = sync_rolling_state(s.seed, target) ^ s.ctx.env_poison;
    }
    return dispatch_next(s);
}

VPACK_CODE bool h_add_image_base(VmExecState& s) noexcept {
    uint8_t dst = 0;
    if (!s.read_u8(dst) || dst >= REG_COUNT) return false;
#if defined(_M_X64) || defined(__x86_64__)
    const auto* peb = reinterpret_cast<const uint8_t*>(__readgsqword(0x60));
    const uint64_t img_base = peb ? *reinterpret_cast<const uint64_t*>(peb + 0x10) : 0ULL;
#else
    const uint64_t img_base = 0ULL;
#endif
    s.ctx.vreg(dst) = crypto::mba_add(s.ctx.vreg(dst), img_base);
    return dispatch_next(s);
}

VPACK_CODE bool h_call_abs(VmExecState& s) noexcept {
    uint8_t target_reg = 0;
    if (!s.read_u8(target_reg) || target_reg >= REG_COUNT) return false;
    const uintptr_t target_va = static_cast<uintptr_t>(s.ctx.vreg(target_reg));
    if (target_va == 0) return false;

    uint64_t arg5 = 0;
    uint64_t arg6 = 0;
    const uintptr_t sp = static_cast<uintptr_t>(s.ctx.vreg(R4));
    const uintptr_t frame_start = reinterpret_cast<uintptr_t>(s.ctx.scratch_frame.data());
    const uintptr_t frame_end   = frame_start + s.ctx.scratch_frame.size();
    if (sp >= frame_start && sp + 0x30 <= frame_end) {
        std::memcpy(&arg5, reinterpret_cast<const void*>(sp + 0x20), sizeof(uint64_t));
        std::memcpy(&arg6, reinterpret_cast<const void*>(sp + 0x28), sizeof(uint64_t));
    }

    using FnNative6 = uint64_t(*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
    auto fn = reinterpret_cast<FnNative6>(reinterpret_cast<void*>(target_va));
    s.ctx.vreg(R0) = fn(
        s.ctx.vreg(R1),
        s.ctx.vreg(R2),
        s.ctx.vreg(R8),
        s.ctx.vreg(R9),
        arg5,
        arg6
    );
    return dispatch_next(s);
}

// Flagless effective-address MBA addition (does NOT modify ctx.flags)
VPACK_CODE bool h_lea_add(VmExecState& s) noexcept {
    uint8_t dst = 0, src = 0;
    if (!s.read_u8(dst) || !s.read_u8(src) || dst >= REG_COUNT || src >= REG_COUNT) return false;
    s.ctx.vreg(dst) = crypto::mba_add(s.ctx.vreg(dst), s.ctx.vreg(src));
    return dispatch_next(s);
}

// Flagless effective-address scale shift (does NOT modify ctx.flags)
VPACK_CODE bool h_lea_shl(VmExecState& s) noexcept {
    uint8_t dst = 0, shift = 0;
    if (!s.read_u8(dst) || !s.read_u8(shift) || dst >= REG_COUNT) return false;
    s.ctx.vreg(dst) <<= (shift & 63u);
    return dispatch_next(s);
}

VPACK_CODE bool h_save_flags(VmExecState& s) noexcept {
    s.ctx.saved_flags = s.ctx.flags;
    return dispatch_next(s);
}

VPACK_CODE bool h_restore_flags(VmExecState& s) noexcept {
    s.ctx.flags = s.ctx.saved_flags;
    return dispatch_next(s);
}

} // namespace

BytecodeBuilder::BytecodeBuilder(uint64_t seed)
    : seed_(seed), op_table_(PolymorphicOpcodeTable::generate_constexpr(seed)) {}

void BytecodeBuilder::emit_op(LogicalOpcode op) {
    raw_code_.push_back(op_table_.logical_to_physical[static_cast<uint8_t>(op)]);
}

void BytecodeBuilder::emit_u8(uint8_t v) {
    raw_code_.push_back(v);
}

void BytecodeBuilder::emit_u16(uint16_t v) {
    raw_code_.push_back(static_cast<uint8_t>(v & 0xFF));
    raw_code_.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
}

void BytecodeBuilder::emit_u32(uint32_t v) {
    for (int i = 0; i < 4; ++i) {
        raw_code_.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
    }
}

void BytecodeBuilder::emit_u64(uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        raw_code_.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
    }
}

void BytecodeBuilder::emit_branch(LogicalOpcode op, const std::string& label_name) {
    emit_op(op);
    fixups_.push_back(Fixup{raw_code_.size(), label_name});
    emit_u32(0);
}

BytecodeBuilder& BytecodeBuilder::nop() {
    emit_op(OP_NOP);
    return *this;
}

BytecodeBuilder& BytecodeBuilder::mov_imm(VmReg dst, uint64_t imm) {
    emit_op(OP_MOV_IMM);
    emit_u8(static_cast<uint8_t>(dst));
    emit_u64(imm);
    return *this;
}

BytecodeBuilder& BytecodeBuilder::mov_reg(VmReg dst, VmReg src) {
    emit_op(OP_MOV_REG);
    emit_u8(static_cast<uint8_t>(dst));
    emit_u8(static_cast<uint8_t>(src));
    return *this;
}

BytecodeBuilder& BytecodeBuilder::add_reg(VmReg dst, VmReg src) {
    emit_op(OP_ADD_REG);
    emit_u8(static_cast<uint8_t>(dst));
    emit_u8(static_cast<uint8_t>(src));
    return *this;
}

BytecodeBuilder& BytecodeBuilder::add_imm(VmReg dst, uint64_t imm) {
    emit_op(OP_ADD_IMM);
    emit_u8(static_cast<uint8_t>(dst));
    emit_u64(imm);
    return *this;
}

BytecodeBuilder& BytecodeBuilder::sub_reg(VmReg dst, VmReg src) {
    emit_op(OP_SUB_REG);
    emit_u8(static_cast<uint8_t>(dst));
    emit_u8(static_cast<uint8_t>(src));
    return *this;
}

BytecodeBuilder& BytecodeBuilder::sub_imm(VmReg dst, uint64_t imm) {
    emit_op(OP_SUB_IMM);
    emit_u8(static_cast<uint8_t>(dst));
    emit_u64(imm);
    return *this;
}

BytecodeBuilder& BytecodeBuilder::imul_reg(VmReg dst, VmReg src) {
    emit_op(OP_IMUL_REG);
    emit_u8(static_cast<uint8_t>(dst));
    emit_u8(static_cast<uint8_t>(src));
    return *this;
}

BytecodeBuilder& BytecodeBuilder::xor_reg(VmReg dst, VmReg src) {
    emit_op(OP_XOR_REG);
    emit_u8(static_cast<uint8_t>(dst));
    emit_u8(static_cast<uint8_t>(src));
    return *this;
}

BytecodeBuilder& BytecodeBuilder::xor_imm(VmReg dst, uint64_t imm) {
    emit_op(OP_XOR_IMM);
    emit_u8(static_cast<uint8_t>(dst));
    emit_u64(imm);
    return *this;
}

BytecodeBuilder& BytecodeBuilder::and_reg(VmReg dst, VmReg src) {
    emit_op(OP_AND_REG);
    emit_u8(static_cast<uint8_t>(dst));
    emit_u8(static_cast<uint8_t>(src));
    return *this;
}

BytecodeBuilder& BytecodeBuilder::or_reg(VmReg dst, VmReg src) {
    emit_op(OP_OR_REG);
    emit_u8(static_cast<uint8_t>(dst));
    emit_u8(static_cast<uint8_t>(src));
    return *this;
}

BytecodeBuilder& BytecodeBuilder::shl_imm(VmReg dst, uint8_t shift) {
    emit_op(OP_SHL_IMM);
    emit_u8(static_cast<uint8_t>(dst));
    emit_u8(shift);
    return *this;
}

BytecodeBuilder& BytecodeBuilder::shr_imm(VmReg dst, uint8_t shift) {
    emit_op(OP_SHR_IMM);
    emit_u8(static_cast<uint8_t>(dst));
    emit_u8(shift);
    return *this;
}

BytecodeBuilder& BytecodeBuilder::sar_imm(VmReg dst, uint8_t shift) {
    emit_op(OP_SAR_IMM);
    emit_u8(static_cast<uint8_t>(dst));
    emit_u8(shift);
    return *this;
}

BytecodeBuilder& BytecodeBuilder::shl_reg(VmReg dst, VmReg shift_reg) {
    emit_op(OP_SHL_REG);
    emit_u8(static_cast<uint8_t>(dst));
    emit_u8(static_cast<uint8_t>(shift_reg));
    return *this;
}

BytecodeBuilder& BytecodeBuilder::shr_reg(VmReg dst, VmReg shift_reg) {
    emit_op(OP_SHR_REG);
    emit_u8(static_cast<uint8_t>(dst));
    emit_u8(static_cast<uint8_t>(shift_reg));
    return *this;
}

BytecodeBuilder& BytecodeBuilder::sar_reg(VmReg dst, VmReg shift_reg) {
    emit_op(OP_SAR_REG);
    emit_u8(static_cast<uint8_t>(dst));
    emit_u8(static_cast<uint8_t>(shift_reg));
    return *this;
}

BytecodeBuilder& BytecodeBuilder::rol_imm(VmReg dst, uint8_t shift) {
    emit_op(OP_ROL_IMM);
    emit_u8(static_cast<uint8_t>(dst));
    emit_u8(shift);
    return *this;
}

BytecodeBuilder& BytecodeBuilder::ror_imm(VmReg dst, uint8_t shift) {
    emit_op(OP_ROR_IMM);
    emit_u8(static_cast<uint8_t>(dst));
    emit_u8(shift);
    return *this;
}

BytecodeBuilder& BytecodeBuilder::not_reg(VmReg dst) {
    emit_op(OP_NOT_REG);
    emit_u8(static_cast<uint8_t>(dst));
    return *this;
}

BytecodeBuilder& BytecodeBuilder::neg_reg(VmReg dst) {
    emit_op(OP_NEG_REG);
    emit_u8(static_cast<uint8_t>(dst));
    return *this;
}

BytecodeBuilder& BytecodeBuilder::movzx32(VmReg dst, VmReg src) {
    emit_op(OP_MOVZX32);
    emit_u8(static_cast<uint8_t>(dst));
    emit_u8(static_cast<uint8_t>(src));
    return *this;
}

BytecodeBuilder& BytecodeBuilder::cmp_reg(VmReg lhs, VmReg rhs) {
    emit_op(OP_CMP_REG);
    emit_u8(static_cast<uint8_t>(lhs));
    emit_u8(static_cast<uint8_t>(rhs));
    return *this;
}

BytecodeBuilder& BytecodeBuilder::cmp_imm(VmReg lhs, uint64_t imm) {
    emit_op(OP_CMP_IMM);
    emit_u8(static_cast<uint8_t>(lhs));
    emit_u64(imm);
    return *this;
}

BytecodeBuilder& BytecodeBuilder::label(const std::string& name) {
    emit_op(OP_SYNC_STATE);
    const uint32_t target = static_cast<uint32_t>(raw_code_.size());
    labels_[name] = target;
    sync_offsets_.push_back(target);
    return *this;
}

BytecodeBuilder& BytecodeBuilder::jmp(const std::string& target_label) {
    emit_branch(OP_JMP, target_label);
    return *this;
}

BytecodeBuilder& BytecodeBuilder::jz(const std::string& target_label) {
    emit_branch(OP_JZ, target_label);
    return *this;
}

BytecodeBuilder& BytecodeBuilder::jnz(const std::string& target_label) {
    emit_branch(OP_JNZ, target_label);
    return *this;
}

BytecodeBuilder& BytecodeBuilder::jg(const std::string& target_label) {
    emit_branch(OP_JG, target_label);
    return *this;
}

BytecodeBuilder& BytecodeBuilder::jl(const std::string& target_label) {
    emit_branch(OP_JL, target_label);
    return *this;
}

BytecodeBuilder& BytecodeBuilder::jge(const std::string& target_label) {
    emit_branch(OP_JGE, target_label);
    return *this;
}

BytecodeBuilder& BytecodeBuilder::jle(const std::string& target_label) {
    emit_branch(OP_JLE, target_label);
    return *this;
}

BytecodeBuilder& BytecodeBuilder::ja(const std::string& target_label) {
    emit_branch(OP_JA, target_label);
    return *this;
}

BytecodeBuilder& BytecodeBuilder::jb(const std::string& target_label) {
    emit_branch(OP_JB, target_label);
    return *this;
}

BytecodeBuilder& BytecodeBuilder::jae(const std::string& target_label) {
    emit_branch(OP_JAE, target_label);
    return *this;
}

BytecodeBuilder& BytecodeBuilder::jbe(const std::string& target_label) {
    emit_branch(OP_JBE, target_label);
    return *this;
}

BytecodeBuilder& BytecodeBuilder::js(const std::string& target_label) {
    emit_branch(OP_JS, target_label);
    return *this;
}

BytecodeBuilder& BytecodeBuilder::jns(const std::string& target_label) {
    emit_branch(OP_JNS, target_label);
    return *this;
}

BytecodeBuilder& BytecodeBuilder::jo(const std::string& target_label) {
    emit_branch(OP_JO, target_label);
    return *this;
}

BytecodeBuilder& BytecodeBuilder::jno(const std::string& target_label) {
    emit_branch(OP_JNO, target_label);
    return *this;
}

BytecodeBuilder& BytecodeBuilder::push(VmReg src) {
    emit_op(OP_PUSH_REG);
    emit_u8(static_cast<uint8_t>(src));
    return *this;
}

BytecodeBuilder& BytecodeBuilder::pop(VmReg dst) {
    emit_op(OP_POP_REG);
    emit_u8(static_cast<uint8_t>(dst));
    return *this;
}

BytecodeBuilder& BytecodeBuilder::load8(VmReg dst, VmReg addr_reg) {
    emit_op(OP_LOAD8);
    emit_u8(static_cast<uint8_t>(dst));
    emit_u8(static_cast<uint8_t>(addr_reg));
    return *this;
}

BytecodeBuilder& BytecodeBuilder::load16(VmReg dst, VmReg addr_reg) {
    emit_op(OP_LOAD16);
    emit_u8(static_cast<uint8_t>(dst));
    emit_u8(static_cast<uint8_t>(addr_reg));
    return *this;
}

BytecodeBuilder& BytecodeBuilder::load32(VmReg dst, VmReg addr_reg) {
    emit_op(OP_LOAD32);
    emit_u8(static_cast<uint8_t>(dst));
    emit_u8(static_cast<uint8_t>(addr_reg));
    return *this;
}

BytecodeBuilder& BytecodeBuilder::load64(VmReg dst, VmReg addr_reg) {
    emit_op(OP_LOAD64);
    emit_u8(static_cast<uint8_t>(dst));
    emit_u8(static_cast<uint8_t>(addr_reg));
    return *this;
}

BytecodeBuilder& BytecodeBuilder::store8(VmReg addr_reg, VmReg src) {
    emit_op(OP_STORE8);
    emit_u8(static_cast<uint8_t>(addr_reg));
    emit_u8(static_cast<uint8_t>(src));
    return *this;
}

BytecodeBuilder& BytecodeBuilder::store16(VmReg addr_reg, VmReg src) {
    emit_op(OP_STORE16);
    emit_u8(static_cast<uint8_t>(addr_reg));
    emit_u8(static_cast<uint8_t>(src));
    return *this;
}

BytecodeBuilder& BytecodeBuilder::store32(VmReg addr_reg, VmReg src) {
    emit_op(OP_STORE32);
    emit_u8(static_cast<uint8_t>(addr_reg));
    emit_u8(static_cast<uint8_t>(src));
    return *this;
}

BytecodeBuilder& BytecodeBuilder::store64(VmReg addr_reg, VmReg src) {
    emit_op(OP_STORE64);
    emit_u8(static_cast<uint8_t>(addr_reg));
    emit_u8(static_cast<uint8_t>(src));
    return *this;
}

BytecodeBuilder& BytecodeBuilder::add_image_base(VmReg dst) {
    emit_op(OP_ADD_IMAGE_BASE);
    emit_u8(static_cast<uint8_t>(dst));
    return *this;
}

BytecodeBuilder& BytecodeBuilder::call_abs(VmReg target_reg) {
    emit_op(OP_CALL_ABS);
    emit_u8(static_cast<uint8_t>(target_reg));
    return *this;
}

BytecodeBuilder& BytecodeBuilder::lea_add(VmReg dst, VmReg src) {
    emit_op(OP_LEA_ADD);
    emit_u8(static_cast<uint8_t>(dst));
    emit_u8(static_cast<uint8_t>(src));
    return *this;
}

BytecodeBuilder& BytecodeBuilder::lea_shl(VmReg dst, uint8_t shift) {
    emit_op(OP_LEA_SHL);
    emit_u8(static_cast<uint8_t>(dst));
    emit_u8(shift);
    return *this;
}

BytecodeBuilder& BytecodeBuilder::save_flags() {
    emit_op(OP_SAVE_FLAGS);
    return *this;
}

BytecodeBuilder& BytecodeBuilder::restore_flags() {
    emit_op(OP_RESTORE_FLAGS);
    return *this;
}

BytecodeBuilder& BytecodeBuilder::call_native(uint16_t slot_id, VmReg dst_ret) {
    emit_op(OP_CALL_NATIVE);
    emit_u16(slot_id);
    emit_u8(static_cast<uint8_t>(dst_ret));
    return *this;
}

BytecodeBuilder& BytecodeBuilder::anti_debug_check() {
    emit_op(OP_ANTI_DEBUG_CHECK);
    return *this;
}

BytecodeBuilder& BytecodeBuilder::mba_add(VmReg dst, VmReg src) {
    emit_op(OP_MBA_ADD);
    emit_u8(static_cast<uint8_t>(dst));
    emit_u8(static_cast<uint8_t>(src));
    return *this;
}

BytecodeBuilder& BytecodeBuilder::mba_sub(VmReg dst, VmReg src) {
    emit_op(OP_MBA_SUB);
    emit_u8(static_cast<uint8_t>(dst));
    emit_u8(static_cast<uint8_t>(src));
    return *this;
}

BytecodeBuilder& BytecodeBuilder::mba_xor(VmReg dst, VmReg src) {
    emit_op(OP_MBA_XOR);
    emit_u8(static_cast<uint8_t>(dst));
    emit_u8(static_cast<uint8_t>(src));
    return *this;
}

BytecodeBuilder& BytecodeBuilder::gf2_mul(VmReg dst, VmReg src) {
    emit_op(OP_GF2_MUL);
    emit_u8(static_cast<uint8_t>(dst));
    emit_u8(static_cast<uint8_t>(src));
    return *this;
}

BytecodeBuilder& BytecodeBuilder::rotate_regs(uint8_t step) {
    emit_op(OP_ROTATE_REGS);
    emit_u8(step);
    return *this;
}

BytecodeBuilder& BytecodeBuilder::state_matrix(uint8_t matrix_key) {
    emit_op(OP_STATE_MATRIX);
    emit_u8(matrix_key);
    return *this;
}

BytecodeBuilder& BytecodeBuilder::entangle_env(VmReg target_reg) {
    emit_op(OP_ENTANGLE_ENV);
    emit_u8(static_cast<uint8_t>(target_reg));
    return *this;
}

BytecodeBuilder& BytecodeBuilder::ret() {
    emit_op(OP_RET);
    return *this;
}

VmProgram BytecodeBuilder::finalize() const {
    std::vector<uint8_t> resolved = raw_code_;
    for (const auto& fix : fixups_) {
        auto it = labels_.find(fix.label_name);
        if (it == labels_.end()) {
            return VmProgram{};
        }
        uint32_t target = it->second;
        for (int i = 0; i < 4; ++i) {
            resolved[fix.offset + i] = static_cast<uint8_t>((target >> (i * 8)) & 0xFF);
        }
    }

    uint64_t rolling_state = sync_rolling_state(seed_, 0);
    for (size_t idx = 0; idx < resolved.size(); ++idx) {
        for (uint32_t sync_off : sync_offsets_) {
            if (sync_off == idx) {
                rolling_state = sync_rolling_state(seed_, idx);
                break;
            }
        }
        uint8_t plain = resolved[idx];
        uint8_t ks    = rolling_stream_byte(rolling_state, idx, seed_);
        resolved[idx] = static_cast<uint8_t>(plain ^ ks);
        rolling_state = step_rolling_state(rolling_state, plain, idx, seed_);
    }

    uint64_t tag = compute_ciphertext_tag(resolved.data(), resolved.size(), seed_);

    VmProgram prog;
    prog.seed          = seed_;
    prog.integrity_tag = tag;
    prog.bytecode      = std::move(resolved);
    return prog;
}

void VmEngine::register_native(uint16_t slot_id, NativeCallback fn) {
    native_table_[slot_id] = fn;
}

namespace {

VPACK_CODE bool execute_protected_vm(
    const VmProgram& program,
    VmContext& ctx,
    const std::unordered_map<uint16_t, NativeCallback>& native_table,
    bool jit_tampered,
    uint64_t* out_return_value
) noexcept {
    if (program.bytecode.empty()) {
        return false;
    }

    // 1. Verify integrity tag DIRECTLY on the ciphertext without ever bulk-decrypting in RAM!
    const uint64_t computed_tag = compute_ciphertext_tag(
        program.bytecode.data(), program.bytecode.size(), program.seed
    );
    if (computed_tag != program.integrity_tag) {
        ctx.tampered = true;
        ctx.halted   = true;
        return false;
    }

    // 2. Superimpose an additional per-execution ephemeral RDTSC stream over the rolling ciphertext
    std::vector<uint8_t> code = program.bytecode;
    const uint64_t ephemeral_key = __rdtsc() ^ program.seed ^ 0xA59E3779B97F4A7CULL;
    for (size_t i = 0; i < code.size(); ++i) {
        code[i] ^= ephemeral_stream_byte(ephemeral_key, i);
    }

    if (jit_tampered) {
        ctx.env_poison ^= 0xBAD0C0DE1337BEEFULL;
        ctx.tampered = true;
    }

    const uintptr_t runtime_ptr_mask = kHandlerPtrMask ^ static_cast<uintptr_t>(ephemeral_key);
    const std::array<uintptr_t, OP_MAX_COUNT> encrypted_handlers = {
        encode_handler_slot(&h_nop,              runtime_ptr_mask, 0),
        encode_handler_slot(&h_mov_imm,          runtime_ptr_mask, 1),
        encode_handler_slot(&h_mov_reg,          runtime_ptr_mask, 2),
        encode_handler_slot(&h_add_reg,          runtime_ptr_mask, 3),
        encode_handler_slot(&h_add_imm,          runtime_ptr_mask, 4),
        encode_handler_slot(&h_sub_reg,          runtime_ptr_mask, 5),
        encode_handler_slot(&h_sub_imm,          runtime_ptr_mask, 6),
        encode_handler_slot(&h_imul_reg,         runtime_ptr_mask, 7),
        encode_handler_slot(&h_xor_reg,          runtime_ptr_mask, 8),
        encode_handler_slot(&h_xor_imm,          runtime_ptr_mask, 9),
        encode_handler_slot(&h_and_reg,          runtime_ptr_mask, 10),
        encode_handler_slot(&h_or_reg,           runtime_ptr_mask, 11),
        encode_handler_slot(&h_shl_imm,          runtime_ptr_mask, 12),
        encode_handler_slot(&h_shr_imm,          runtime_ptr_mask, 13),
        encode_handler_slot(&h_rol_imm,          runtime_ptr_mask, 14),
        encode_handler_slot(&h_ror_imm,          runtime_ptr_mask, 15),
        encode_handler_slot(&h_not_reg,          runtime_ptr_mask, 16),
        encode_handler_slot(&h_neg_reg,          runtime_ptr_mask, 17),
        encode_handler_slot(&h_cmp_reg,          runtime_ptr_mask, 18),
        encode_handler_slot(&h_cmp_imm,          runtime_ptr_mask, 19),
        encode_handler_slot(&h_jmp,              runtime_ptr_mask, 20),
        encode_handler_slot(&h_jz,               runtime_ptr_mask, 21),
        encode_handler_slot(&h_jnz,              runtime_ptr_mask, 22),
        encode_handler_slot(&h_jg,               runtime_ptr_mask, 23),
        encode_handler_slot(&h_jl,               runtime_ptr_mask, 24),
        encode_handler_slot(&h_push_reg,         runtime_ptr_mask, 25),
        encode_handler_slot(&h_pop_reg,          runtime_ptr_mask, 26),
        encode_handler_slot(&h_load64,           runtime_ptr_mask, 27),
        encode_handler_slot(&h_store64,          runtime_ptr_mask, 28),
        encode_handler_slot(&h_call_native,      runtime_ptr_mask, 29),
        encode_handler_slot(&h_anti_debug_check, runtime_ptr_mask, 30),
        encode_handler_slot(&h_sync_state,       runtime_ptr_mask, 31),
        encode_handler_slot(&h_mba_add,          runtime_ptr_mask, 32),
        encode_handler_slot(&h_mba_sub,          runtime_ptr_mask, 33),
        encode_handler_slot(&h_mba_xor,          runtime_ptr_mask, 34),
        encode_handler_slot(&h_gf2_mul,          runtime_ptr_mask, 35),
        encode_handler_slot(&h_rotate_regs,      runtime_ptr_mask, 36),
        encode_handler_slot(&h_state_matrix,     runtime_ptr_mask, 37),
        encode_handler_slot(&h_entangle_env,     runtime_ptr_mask, 38),
        encode_handler_slot(&h_jge,              runtime_ptr_mask, 39),
        encode_handler_slot(&h_jle,              runtime_ptr_mask, 40),
        encode_handler_slot(&h_ja,               runtime_ptr_mask, 41),
        encode_handler_slot(&h_jb,               runtime_ptr_mask, 42),
        encode_handler_slot(&h_jae,              runtime_ptr_mask, 43),
        encode_handler_slot(&h_jbe,              runtime_ptr_mask, 44),
        encode_handler_slot(&h_shl_reg,          runtime_ptr_mask, 45),
        encode_handler_slot(&h_shr_reg,          runtime_ptr_mask, 46),
        encode_handler_slot(&h_sar_imm,          runtime_ptr_mask, 47),
        encode_handler_slot(&h_movzx32,          runtime_ptr_mask, 48),
        encode_handler_slot(&h_ret,              runtime_ptr_mask, 49),
        encode_handler_slot(&h_load8,            runtime_ptr_mask, 50),
        encode_handler_slot(&h_load16,           runtime_ptr_mask, 51),
        encode_handler_slot(&h_load32,           runtime_ptr_mask, 52),
        encode_handler_slot(&h_store8,           runtime_ptr_mask, 53),
        encode_handler_slot(&h_store16,          runtime_ptr_mask, 54),
        encode_handler_slot(&h_store32,          runtime_ptr_mask, 55),
        encode_handler_slot(&h_sar_reg,          runtime_ptr_mask, 56),
        encode_handler_slot(&h_js,               runtime_ptr_mask, 57),
        encode_handler_slot(&h_jns,              runtime_ptr_mask, 58),
        encode_handler_slot(&h_jo,               runtime_ptr_mask, 59),
        encode_handler_slot(&h_jno,              runtime_ptr_mask, 60),
        encode_handler_slot(&h_add_image_base,   runtime_ptr_mask, 61),
        encode_handler_slot(&h_call_abs,         runtime_ptr_mask, 62),
        encode_handler_slot(&h_lea_add,          runtime_ptr_mask, 63),
        encode_handler_slot(&h_lea_shl,          runtime_ptr_mask, 64),
        encode_handler_slot(&h_save_flags,       runtime_ptr_mask, 65),
        encode_handler_slot(&h_restore_flags,    runtime_ptr_mask, 66)
    };

    for (uint8_t i = 0; i < REG_COUNT; ++i) {
        ctx.reg_map[i] = i;
    }

    const PolymorphicOpcodeTable op_table = PolymorphicOpcodeTable::generate_constexpr(program.seed);
    VmExecState state{
        ctx,
        code,
        code.size(),
        program.seed,
        ephemeral_key,
        runtime_ptr_mask,
        op_table,
        encrypted_handlers,
        native_table
    };

    ctx.ip            = 0;
    ctx.rolling_state = sync_rolling_state(program.seed, 0) ^ ctx.env_poison;
    ctx.stack_key     = ephemeral_key ^ 0xF19D83A5C7E24B19ULL;
    ctx.halted        = false;
    ctx.tampered      = jit_tampered;

    const bool ok = dispatch_next(state);

    const uint64_t final_r0 = ctx.vreg(R0);
    ctx.regs[R0] = final_r0;
    if (out_return_value) {
        *out_return_value = final_r0;
    }

    crypto::secure_wipe(code.data(), code.size(), ephemeral_key);
    return ok && ctx.halted && !ctx.tampered;
}

} // namespace

bool VmEngine::execute(const VmProgram& program, VmContext& ctx, uint64_t* out_return_value) const noexcept {
    antidump::JitSectionGuard jit_guard;
    return execute_protected_vm(program, ctx, native_table_, jit_guard.is_tampered(), out_return_value);
}

uint64_t VmEngine::run_WithArgs(
    const VmProgram& program,
    uint64_t r0,
    uint64_t r1,
    uint64_t r2,
    uint64_t r3,
    bool* out_ok
) const noexcept {
    VmContext ctx;
    ctx.regs[R0] = r0;
    ctx.regs[R1] = r1;
    ctx.regs[R2] = r2;
    ctx.regs[R3] = r3;

    uint64_t ret = 0;
    bool ok = execute(program, ctx, &ret);
    if (out_ok) *out_ok = ok;
    crypto::secure_wipe(ctx.regs.data(), sizeof(ctx.regs), ret);
    return ret;
}

uint64_t VmEngine::run_x64_abi(
    const VmProgram& program,
    uint64_t rcx_arg,
    uint64_t rdx_arg,
    uint64_t r8_arg,
    uint64_t r9_arg,
    bool* out_ok
) const noexcept {
    VmContext ctx;
    // Map Windows x64 ABI argument registers (RCX=1, RDX=2, R8=8, R9=9) and stack pointer (RSP=4)
    ctx.regs[R1] = rcx_arg;
    ctx.regs[R2] = rdx_arg;
    ctx.regs[R8] = r8_arg;
    ctx.regs[R9] = r9_arg;
    ctx.regs[R4] = (reinterpret_cast<uint64_t>(ctx.scratch_frame.data() + 1024) & ~0xFULL) - 8ULL;

    uint64_t ret = 0;
    bool ok = execute(program, ctx, &ret);
    if (out_ok) *out_ok = ok;
    crypto::secure_wipe(ctx.regs.data(), sizeof(ctx.regs), ret);
    crypto::secure_wipe(ctx.scratch_frame.data(), ctx.scratch_frame.size(), ret ^ 0x9E3779B97F4A7C15ULL);
    return ret;
}

} // namespace vpack::vm
