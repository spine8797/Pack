#include "vpack/vm.h"
#include "vpack/crypto.h"
#include "vpack/anti_debug.h"
#include <intrin.h>
#include <cstring>
#include <cstdlib>

namespace vpack::vm {

namespace {

VPACK_FORCEINLINE uint64_t splitmix64(uint64_t& state) noexcept {
    uint64_t z = (state += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

// Position-independent ephemeral stream byte so random-access jumps (JMP/JZ/JNZ)
// decrypt single bytes in registers without ever holding plaintext bytecode in RAM.
VPACK_FORCEINLINE uint8_t ephemeral_stream_byte(uint64_t key, size_t idx) noexcept {
    uint64_t x = key ^ (static_cast<uint64_t>(idx) * 0x9E3779B97F4A7C15ULL);
    x ^= (x >> 30);
    x *= 0xBF58476D1CE4E5B9ULL;
    x ^= (x >> 27);
    return static_cast<uint8_t>((x ^ (x >> 31)) & 0xFFu);
}

VPACK_FORCEINLINE void update_cmp_flags(VmContext& ctx, uint64_t lhs, uint64_t rhs) noexcept {
    uint64_t res = lhs - rhs;
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

VPACK_FORCEINLINE void update_alu_flags(VmContext& ctx, uint64_t val) noexcept {
    ctx.flags &= ~(FLAG_ZF | FLAG_SF);
    if (val == 0) ctx.flags |= FLAG_ZF;
    if ((val >> 63) & 1ULL) ctx.flags |= FLAG_SF;
}

constexpr uintptr_t kHandlerPtrMask = static_cast<uintptr_t>(0xD6E8FEB86659FD93ULL);

struct VmExecState;
using VmHandlerFn = bool(*)(VmExecState&) noexcept;

struct VmExecState {
    VmContext&                                          ctx;
    std::vector<uint8_t>&                               code;
    size_t                                              code_size;
    uint64_t                                            ephemeral_key;
    uintptr_t                                           runtime_ptr_mask;
    const PolymorphicOpcodeTable&                       op_table;
    const std::array<uintptr_t, OP_MAX_COUNT>&          encrypted_handlers;
    const std::unordered_map<uint16_t, NativeCallback>& native_table;

    VPACK_FORCEINLINE bool read_u8(uint8_t& out) noexcept {
        if (ctx.ip >= code_size) return false;
        const size_t idx = ctx.ip++;
        out = static_cast<uint8_t>(code[idx] ^ ephemeral_stream_byte(ephemeral_key, idx));
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

// Direct Threaded Dispatch: each handler chains directly to the next handler (no central loop!)
VPACK_CODE bool dispatch_next(VmExecState& s) noexcept {
    if (s.ctx.halted || s.ctx.ip >= s.code_size) {
        return s.ctx.halted && !s.ctx.tampered;
    }

    uint8_t phys_op = 0;
    if (!s.read_u8(phys_op)) {
        return false;
    }

    const uint8_t logical_op = s.op_table.physical_to_logical[phys_op];
    if (logical_op >= OP_MAX_COUNT) {
        s.ctx.tampered = true;
        s.ctx.halted = true;
        return false;
    }

    const uintptr_t raw_fn = s.encrypted_handlers[logical_op] ^ s.runtime_ptr_mask ^
                             (static_cast<uintptr_t>(logical_op) * 0x9E3779B9u);
    const auto next_handler = reinterpret_cast<VmHandlerFn>(reinterpret_cast<void*>(raw_fn));
    return next_handler(s);
}

VPACK_CODE bool h_nop(VmExecState& s) noexcept {
    return dispatch_next(s);
}

VPACK_CODE bool h_mov_imm(VmExecState& s) noexcept {
    uint8_t dst = 0; uint64_t imm = 0;
    if (!s.read_u8(dst) || !s.read_u64(imm) || dst >= REG_COUNT) return false;
    s.ctx.regs[dst] = imm;
    return dispatch_next(s);
}

VPACK_CODE bool h_mov_reg(VmExecState& s) noexcept {
    uint8_t dst = 0, src = 0;
    if (!s.read_u8(dst) || !s.read_u8(src) || dst >= REG_COUNT || src >= REG_COUNT) return false;
    s.ctx.regs[dst] = s.ctx.regs[src];
    return dispatch_next(s);
}

VPACK_CODE bool h_add_reg(VmExecState& s) noexcept {
    uint8_t dst = 0, src = 0;
    if (!s.read_u8(dst) || !s.read_u8(src) || dst >= REG_COUNT || src >= REG_COUNT) return false;
    s.ctx.regs[dst] += s.ctx.regs[src];
    update_alu_flags(s.ctx, s.ctx.regs[dst]);
    return dispatch_next(s);
}

VPACK_CODE bool h_add_imm(VmExecState& s) noexcept {
    uint8_t dst = 0; uint64_t imm = 0;
    if (!s.read_u8(dst) || !s.read_u64(imm) || dst >= REG_COUNT) return false;
    s.ctx.regs[dst] += imm;
    update_alu_flags(s.ctx, s.ctx.regs[dst]);
    return dispatch_next(s);
}

VPACK_CODE bool h_sub_reg(VmExecState& s) noexcept {
    uint8_t dst = 0, src = 0;
    if (!s.read_u8(dst) || !s.read_u8(src) || dst >= REG_COUNT || src >= REG_COUNT) return false;
    s.ctx.regs[dst] -= s.ctx.regs[src];
    update_alu_flags(s.ctx, s.ctx.regs[dst]);
    return dispatch_next(s);
}

VPACK_CODE bool h_sub_imm(VmExecState& s) noexcept {
    uint8_t dst = 0; uint64_t imm = 0;
    if (!s.read_u8(dst) || !s.read_u64(imm) || dst >= REG_COUNT) return false;
    s.ctx.regs[dst] -= imm;
    update_alu_flags(s.ctx, s.ctx.regs[dst]);
    return dispatch_next(s);
}

VPACK_CODE bool h_imul_reg(VmExecState& s) noexcept {
    uint8_t dst = 0, src = 0;
    if (!s.read_u8(dst) || !s.read_u8(src) || dst >= REG_COUNT || src >= REG_COUNT) return false;
    s.ctx.regs[dst] *= s.ctx.regs[src];
    update_alu_flags(s.ctx, s.ctx.regs[dst]);
    return dispatch_next(s);
}

VPACK_CODE bool h_xor_reg(VmExecState& s) noexcept {
    uint8_t dst = 0, src = 0;
    if (!s.read_u8(dst) || !s.read_u8(src) || dst >= REG_COUNT || src >= REG_COUNT) return false;
    s.ctx.regs[dst] ^= s.ctx.regs[src];
    update_alu_flags(s.ctx, s.ctx.regs[dst]);
    return dispatch_next(s);
}

VPACK_CODE bool h_xor_imm(VmExecState& s) noexcept {
    uint8_t dst = 0; uint64_t imm = 0;
    if (!s.read_u8(dst) || !s.read_u64(imm) || dst >= REG_COUNT) return false;
    s.ctx.regs[dst] ^= imm;
    update_alu_flags(s.ctx, s.ctx.regs[dst]);
    return dispatch_next(s);
}

VPACK_CODE bool h_and_reg(VmExecState& s) noexcept {
    uint8_t dst = 0, src = 0;
    if (!s.read_u8(dst) || !s.read_u8(src) || dst >= REG_COUNT || src >= REG_COUNT) return false;
    s.ctx.regs[dst] &= s.ctx.regs[src];
    update_alu_flags(s.ctx, s.ctx.regs[dst]);
    return dispatch_next(s);
}

VPACK_CODE bool h_or_reg(VmExecState& s) noexcept {
    uint8_t dst = 0, src = 0;
    if (!s.read_u8(dst) || !s.read_u8(src) || dst >= REG_COUNT || src >= REG_COUNT) return false;
    s.ctx.regs[dst] |= s.ctx.regs[src];
    update_alu_flags(s.ctx, s.ctx.regs[dst]);
    return dispatch_next(s);
}

VPACK_CODE bool h_shl_imm(VmExecState& s) noexcept {
    uint8_t dst = 0, shift = 0;
    if (!s.read_u8(dst) || !s.read_u8(shift) || dst >= REG_COUNT) return false;
    s.ctx.regs[dst] <<= (shift & 63);
    update_alu_flags(s.ctx, s.ctx.regs[dst]);
    return dispatch_next(s);
}

VPACK_CODE bool h_shr_imm(VmExecState& s) noexcept {
    uint8_t dst = 0, shift = 0;
    if (!s.read_u8(dst) || !s.read_u8(shift) || dst >= REG_COUNT) return false;
    s.ctx.regs[dst] >>= (shift & 63);
    update_alu_flags(s.ctx, s.ctx.regs[dst]);
    return dispatch_next(s);
}

VPACK_CODE bool h_rol_imm(VmExecState& s) noexcept {
    uint8_t dst = 0, shift = 0;
    if (!s.read_u8(dst) || !s.read_u8(shift) || dst >= REG_COUNT) return false;
    uint8_t sh = shift & 63;
    if (sh != 0) s.ctx.regs[dst] = (s.ctx.regs[dst] << sh) | (s.ctx.regs[dst] >> (64 - sh));
    update_alu_flags(s.ctx, s.ctx.regs[dst]);
    return dispatch_next(s);
}

VPACK_CODE bool h_ror_imm(VmExecState& s) noexcept {
    uint8_t dst = 0, shift = 0;
    if (!s.read_u8(dst) || !s.read_u8(shift) || dst >= REG_COUNT) return false;
    uint8_t sh = shift & 63;
    if (sh != 0) s.ctx.regs[dst] = (s.ctx.regs[dst] >> sh) | (s.ctx.regs[dst] << (64 - sh));
    update_alu_flags(s.ctx, s.ctx.regs[dst]);
    return dispatch_next(s);
}

VPACK_CODE bool h_not_reg(VmExecState& s) noexcept {
    uint8_t dst = 0;
    if (!s.read_u8(dst) || dst >= REG_COUNT) return false;
    s.ctx.regs[dst] = ~s.ctx.regs[dst];
    update_alu_flags(s.ctx, s.ctx.regs[dst]);
    return dispatch_next(s);
}

VPACK_CODE bool h_neg_reg(VmExecState& s) noexcept {
    uint8_t dst = 0;
    if (!s.read_u8(dst) || dst >= REG_COUNT) return false;
    s.ctx.regs[dst] = static_cast<uint64_t>(-static_cast<int64_t>(s.ctx.regs[dst]));
    update_alu_flags(s.ctx, s.ctx.regs[dst]);
    return dispatch_next(s);
}

VPACK_CODE bool h_cmp_reg(VmExecState& s) noexcept {
    uint8_t lhs = 0, rhs = 0;
    if (!s.read_u8(lhs) || !s.read_u8(rhs) || lhs >= REG_COUNT || rhs >= REG_COUNT) return false;
    update_cmp_flags(s.ctx, s.ctx.regs[lhs], s.ctx.regs[rhs]);
    return dispatch_next(s);
}

VPACK_CODE bool h_cmp_imm(VmExecState& s) noexcept {
    uint8_t lhs = 0; uint64_t imm = 0;
    if (!s.read_u8(lhs) || !s.read_u64(imm) || lhs >= REG_COUNT) return false;
    update_cmp_flags(s.ctx, s.ctx.regs[lhs], imm);
    return dispatch_next(s);
}

VPACK_CODE bool h_jmp(VmExecState& s) noexcept {
    uint32_t target = 0;
    if (!s.read_u32(target) || target >= s.code_size) return false;
    s.ctx.ip = target;
    return dispatch_next(s);
}

VPACK_CODE bool h_jz(VmExecState& s) noexcept {
    uint32_t target = 0;
    if (!s.read_u32(target) || target >= s.code_size) return false;
    if (s.ctx.flags & FLAG_ZF) s.ctx.ip = target;
    return dispatch_next(s);
}

VPACK_CODE bool h_jnz(VmExecState& s) noexcept {
    uint32_t target = 0;
    if (!s.read_u32(target) || target >= s.code_size) return false;
    if (!(s.ctx.flags & FLAG_ZF)) s.ctx.ip = target;
    return dispatch_next(s);
}

VPACK_CODE bool h_jg(VmExecState& s) noexcept {
    uint32_t target = 0;
    if (!s.read_u32(target) || target >= s.code_size) return false;
    bool zf = (s.ctx.flags & FLAG_ZF) != 0;
    bool sf = (s.ctx.flags & FLAG_SF) != 0;
    bool of = (s.ctx.flags & FLAG_OF) != 0;
    if (!zf && (sf == of)) s.ctx.ip = target;
    return dispatch_next(s);
}

VPACK_CODE bool h_jl(VmExecState& s) noexcept {
    uint32_t target = 0;
    if (!s.read_u32(target) || target >= s.code_size) return false;
    bool sf = (s.ctx.flags & FLAG_SF) != 0;
    bool of = (s.ctx.flags & FLAG_OF) != 0;
    if (sf != of) s.ctx.ip = target;
    return dispatch_next(s);
}

VPACK_CODE bool h_push_reg(VmExecState& s) noexcept {
    uint8_t src = 0;
    if (!s.read_u8(src) || src >= REG_COUNT) return false;
    s.ctx.stack.push_back(s.ctx.regs[src]);
    return dispatch_next(s);
}

VPACK_CODE bool h_pop_reg(VmExecState& s) noexcept {
    uint8_t dst = 0;
    if (!s.read_u8(dst) || dst >= REG_COUNT || s.ctx.stack.empty()) return false;
    s.ctx.regs[dst] = s.ctx.stack.back();
    s.ctx.stack.pop_back();
    return dispatch_next(s);
}

VPACK_CODE bool h_load64(VmExecState& s) noexcept {
    uint8_t dst = 0, addr_reg = 0;
    if (!s.read_u8(dst) || !s.read_u8(addr_reg) || dst >= REG_COUNT || addr_reg >= REG_COUNT) return false;
    const auto* ptr = reinterpret_cast<const uint64_t*>(s.ctx.regs[addr_reg]);
    if (!ptr) return false;
    std::memcpy(&s.ctx.regs[dst], ptr, sizeof(uint64_t));
    return dispatch_next(s);
}

VPACK_CODE bool h_store64(VmExecState& s) noexcept {
    uint8_t addr_reg = 0, src = 0;
    if (!s.read_u8(addr_reg) || !s.read_u8(src) || addr_reg >= REG_COUNT || src >= REG_COUNT) return false;
    auto* ptr = reinterpret_cast<uint64_t*>(s.ctx.regs[addr_reg]);
    if (!ptr) return false;
    std::memcpy(ptr, &s.ctx.regs[src], sizeof(uint64_t));
    return dispatch_next(s);
}

VPACK_CODE bool h_call_native(VmExecState& s) noexcept {
    uint16_t slot = 0; uint8_t dst_ret = 0;
    if (!s.read_u16(slot) || !s.read_u8(dst_ret) || dst_ret >= REG_COUNT) return false;
    auto it = s.native_table.find(slot);
    if (it == s.native_table.end() || !it->second) return false;
    s.ctx.regs[dst_ret] = it->second(s.ctx.regs[R0], s.ctx.regs[R1], s.ctx.regs[R2], s.ctx.regs[R3]);
    return dispatch_next(s);
}

VPACK_CODE bool h_anti_debug_check(VmExecState& s) noexcept {
    if (antidebug::check_peb_being_debugged() || antidebug::check_nt_global_flag()) {
        s.ctx.tampered = true;
        s.ctx.flags |= FLAG_TRAP;
        for (auto& r : s.ctx.regs) {
            r ^= 0xDEAD0000BAD00000ULL;
        }
    }
    return dispatch_next(s);
}

VPACK_CODE bool h_ret(VmExecState& s) noexcept {
    s.ctx.halted = true;
    return !s.ctx.tampered;
}

VPACK_FORCEINLINE uintptr_t encode_handler_slot(VmHandlerFn fn, uintptr_t mask, size_t idx) noexcept {
    return reinterpret_cast<uintptr_t>(reinterpret_cast<void*>(fn)) ^ mask ^ (idx * 0x9E3779B9u);
}

} // namespace

PolymorphicOpcodeTable PolymorphicOpcodeTable::generate(uint64_t seed) noexcept {
    PolymorphicOpcodeTable table{};
    for (size_t i = 0; i < 256; ++i) {
        table.logical_to_physical[i] = static_cast<uint8_t>(i);
    }

    uint64_t prng = seed ^ 0xA55AA55A5AA55AA5ULL;
    for (size_t i = 255; i > 0; --i) {
        size_t j = static_cast<size_t>(splitmix64(prng) % (i + 1));
        uint8_t tmp = table.logical_to_physical[i];
        table.logical_to_physical[i] = table.logical_to_physical[j];
        table.logical_to_physical[j] = tmp;
    }

    for (size_t i = 0; i < 256; ++i) {
        table.physical_to_logical[table.logical_to_physical[i]] = static_cast<uint8_t>(i);
    }
    return table;
}

BytecodeBuilder::BytecodeBuilder(uint64_t seed)
    : seed_(seed), op_table_(PolymorphicOpcodeTable::generate(seed)) {}

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
    labels_[name] = static_cast<uint32_t>(raw_code_.size());
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

BytecodeBuilder& BytecodeBuilder::load64(VmReg dst, VmReg addr_reg) {
    emit_op(OP_LOAD64);
    emit_u8(static_cast<uint8_t>(dst));
    emit_u8(static_cast<uint8_t>(addr_reg));
    return *this;
}

BytecodeBuilder& BytecodeBuilder::store64(VmReg addr_reg, VmReg src) {
    emit_op(OP_STORE64);
    emit_u8(static_cast<uint8_t>(addr_reg));
    emit_u8(static_cast<uint8_t>(src));
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

    uint64_t tag = crypto::fnv1a_64(resolved.data(), resolved.size()) ^ seed_;
    crypto::rolling_encrypt(resolved.data(), resolved.size(), seed_);

    VmProgram prog;
    prog.seed = seed_;
    prog.integrity_tag = tag;
    prog.bytecode = std::move(resolved);
    return prog;
}

void VmEngine::register_native(uint16_t slot_id, NativeCallback fn) {
    native_table_[slot_id] = fn;
}

VPACK_CODE bool VmEngine::execute(const VmProgram& program, VmContext& ctx, uint64_t* out_return_value) const noexcept {
    if (program.bytecode.empty()) {
        return false;
    }

    std::vector<uint8_t> code = program.bytecode;
    crypto::rolling_decrypt(code.data(), code.size(), program.seed);

    uint64_t computed_tag = crypto::fnv1a_64(code.data(), code.size()) ^ program.seed;
    if (computed_tag != program.integrity_tag) {
        std::memset(code.data(), 0, code.size());
        ctx.tampered = true;
        ctx.halted = true;
        return false;
    }

    // Immediately re-encrypt bytecode in RAM with an ephemeral per-execution RDTSC key
    // so plaintext bytecode NEVER resides in memory during VM execution!
    const uint64_t ephemeral_key = __rdtsc() ^ program.seed ^ 0xA59E3779B97F4A7CULL;
    for (size_t i = 0; i < code.size(); ++i) {
        code[i] ^= ephemeral_stream_byte(ephemeral_key, i);
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
        encode_handler_slot(&h_ret,              runtime_ptr_mask, 31)
    };

    const PolymorphicOpcodeTable op_table = PolymorphicOpcodeTable::generate(program.seed);
    VmExecState state{
        ctx,
        code,
        code.size(),
        ephemeral_key,
        runtime_ptr_mask,
        op_table,
        encrypted_handlers,
        native_table_
    };

    ctx.ip = 0;
    ctx.halted = false;
    ctx.tampered = false;

    const bool ok = dispatch_next(state);
    std::memset(code.data(), 0, code.size());

    if (out_return_value) {
        *out_return_value = ctx.regs[R0];
    }
    return ok && ctx.halted && !ctx.tampered;
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
    return ret;
}

} // namespace vpack::vm
