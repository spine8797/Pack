#pragma once

#include "vpack/config.h"
#include "vpack/crypto.h"
#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <unordered_map>
#include <array>

namespace vpack::vm {

enum VmReg : uint8_t {
    R0 = 0, R1, R2, R3, R4, R5, R6, R7,
    R8, R9, R10, R11, R12, R13, R14, R15,
    REG_COUNT = 16
};

enum VmFlags : uint32_t {
    FLAG_NONE = 0,
    FLAG_ZF   = 1u << 0,
    FLAG_SF   = 1u << 1,
    FLAG_CF   = 1u << 2,
    FLAG_OF   = 1u << 3,
    FLAG_TRAP = 1u << 7
};

enum LogicalOpcode : uint8_t {
    OP_NOP = 0,
    OP_MOV_IMM,
    OP_MOV_REG,
    OP_ADD_REG,
    OP_ADD_IMM,
    OP_SUB_REG,
    OP_SUB_IMM,
    OP_IMUL_REG,
    OP_XOR_REG,
    OP_XOR_IMM,
    OP_AND_REG,
    OP_OR_REG,
    OP_SHL_IMM,
    OP_SHR_IMM,
    OP_ROL_IMM,
    OP_ROR_IMM,
    OP_NOT_REG,
    OP_NEG_REG,
    OP_CMP_REG,
    OP_CMP_IMM,
    OP_JMP,
    OP_JZ,
    OP_JNZ,
    OP_JG,
    OP_JL,
    OP_PUSH_REG,
    OP_POP_REG,
    OP_LOAD64,
    OP_STORE64,
    OP_CALL_NATIVE,
    OP_ANTI_DEBUG_CHECK,
    // JANUS Hybrid VM Extensions (MBA + GF(2^64) + Dynamic Reg Rotation + State Matrix + Stream Sync)
    OP_SYNC_STATE,
    OP_MBA_ADD,
    OP_MBA_SUB,
    OP_MBA_XOR,
    OP_GF2_MUL,
    OP_ROTATE_REGS,
    OP_STATE_MATRIX,
    OP_ENTANGLE_ENV,
    OP_RET,
    OP_MAX_COUNT
};

// ============================================================================
// Constexpr Polymorphic Opcode Permutation & Rolling Stream Primitives
// Shared between Compile-Time ConstexprVmBuilder and Runtime VmEngine
// ============================================================================
constexpr uint64_t vm_splitmix64(uint64_t& state) noexcept {
    uint64_t z = (state += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

// Synchronizes rolling decryption key at basic-block entry / branch target offset
constexpr VPACK_FORCEINLINE uint64_t sync_rolling_state(uint64_t seed, size_t offset) noexcept {
    const uint64_t mix = seed ^ (static_cast<uint64_t>(offset) * 0x9E3779B97F4A7C15ULL) ^ 0xC983E5A19F27B4D3ULL;
    return crypto::poly_permute_64(mix, seed ^ 0xBF58476D1CE4E5B9ULL);
}

// Extracts 1 keystream byte from current rolling state (Non-Linear MBA + GF(2^64))
constexpr VPACK_FORCEINLINE uint8_t rolling_stream_byte(uint64_t rolling_state, size_t idx, uint64_t seed) noexcept {
    const uint64_t m = crypto::mba_add(rolling_state, static_cast<uint64_t>(idx) * 0x94D049BB133111EBULL);
    const uint64_t p = crypto::mba_xor(m, (seed >> ((idx & 7) * 8)));
    return static_cast<uint8_t>((p ^ (p >> 29) ^ (p >> 17)) & 0xFFu);
}

// Evolves rolling state using the decrypted plaintext byte (Instruction-Chained Rolling Key:
// patching or NOPing any byte in a basic block corrupts all subsequent instructions!)
constexpr VPACK_FORCEINLINE uint64_t step_rolling_state(
    uint64_t rolling_state,
    uint8_t  plain_byte,
    size_t   idx,
    uint64_t seed
) noexcept {
    const uint64_t rot = (rolling_state << 13) | (rolling_state >> 51);
    const uint64_t step = crypto::mba_add(rot, 0x9E3779B97F4A7C15ULL ^ (static_cast<uint64_t>(idx) * 0x100000001B3ULL));
    const uint64_t fb   = static_cast<uint64_t>(plain_byte) * 0xBF58476D1CE4E5B9ULL;
    return crypto::mba_xor(step, fb ^ (seed >> 11));
}

// Computes integrity MAC directly over the encrypted bytecode (so VmEngine never bulk-decrypts in RAM)
constexpr uint64_t compute_ciphertext_tag(const uint8_t* data, size_t size, uint64_t seed) noexcept {
    uint64_t h = 0xCBF29CE484222325ULL ^ seed;
    for (size_t i = 0; i < size; ++i) {
        h ^= static_cast<uint64_t>(data[i]);
        h *= 0x100000001B3ULL;
    }
    return crypto::poly_permute_64(h, seed);
}

struct PolymorphicOpcodeTable {
    std::array<uint8_t, 256> logical_to_physical{};
    std::array<uint8_t, 256> physical_to_logical{};

    static constexpr PolymorphicOpcodeTable generate_constexpr(uint64_t seed) noexcept {
        PolymorphicOpcodeTable table{};
        for (size_t i = 0; i < 256; ++i) {
            table.logical_to_physical[i] = static_cast<uint8_t>(i);
        }
        uint64_t prng = seed ^ 0xA55AA55A5AA55AA5ULL;
        for (size_t i = 255; i > 0; --i) {
            size_t j = static_cast<size_t>(vm_splitmix64(prng) % (i + 1));
            uint8_t tmp = table.logical_to_physical[i];
            table.logical_to_physical[i] = table.logical_to_physical[j];
            table.logical_to_physical[j] = tmp;
        }
        for (size_t i = 0; i < 256; ++i) {
            table.physical_to_logical[table.logical_to_physical[i]] = static_cast<uint8_t>(i);
        }
        return table;
    }

    static PolymorphicOpcodeTable generate(uint64_t seed) noexcept {
        return generate_constexpr(seed);
    }
};

struct VmProgram {
    uint64_t               seed = 0;
    uint64_t               integrity_tag = 0;
    std::vector<uint8_t>   bytecode;
};

template <size_t MaxBytes = 256>
struct ConstexprVmProgram {
    uint64_t                      seed = 0;
    uint64_t                      integrity_tag = 0;
    size_t                        size = 0;
    std::array<uint8_t, MaxBytes> bytecode{};

    VmProgram to_program() const {
        VmProgram prog;
        prog.seed          = seed;
        prog.integrity_tag = integrity_tag;
        prog.bytecode.assign(bytecode.begin(), bytecode.begin() + size);
        return prog;
    }
};

using NativeCallback = uint64_t(*)(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3);

struct VmContext {
    std::array<uint64_t, REG_COUNT> regs{};
    std::array<uint8_t, REG_COUNT>  reg_map{};
    std::vector<uint64_t>           stack;
    size_t                          ip = 0;
    uint64_t                        rolling_state = 0;
    uint64_t                        stack_key = 0;
    uint64_t                        env_poison = 0;
    uint32_t                        flags = FLAG_NONE;
    bool                            halted = false;
    bool                            tampered = false;

    VmContext(size_t stack_depth = 256) {
        stack.reserve(stack_depth);
        for (uint8_t i = 0; i < REG_COUNT; ++i) {
            reg_map[i] = i;
        }
    }

    VPACK_FORCEINLINE uint64_t& vreg(uint8_t logical_reg) noexcept {
        return regs[reg_map[logical_reg & 0x0Fu]];
    }

    VPACK_FORCEINLINE const uint64_t& vreg(uint8_t logical_reg) const noexcept {
        return regs[reg_map[logical_reg & 0x0Fu]];
    }
};

// ============================================================================
// Compile-Time Constexpr VM Bytecode Builder
// Compiles and rolling-encrypts VM programs 100% at C++ compile time so ZERO
// builder calls or plaintext opcodes ever appear in the compiled binary!
// ============================================================================
template <size_t MaxBytes = 256>
class ConstexprVmBuilder {
public:
    constexpr explicit ConstexprVmBuilder(uint64_t seed) noexcept
        : seed_(seed), op_table_(PolymorphicOpcodeTable::generate_constexpr(seed)) {}

    constexpr ConstexprVmBuilder& nop() noexcept { emit_op(OP_NOP); return *this; }
    constexpr ConstexprVmBuilder& mov_imm(VmReg dst, uint64_t imm) noexcept {
        emit_op(OP_MOV_IMM); emit_u8(static_cast<uint8_t>(dst)); emit_u64(imm); return *this;
    }
    constexpr ConstexprVmBuilder& mov_reg(VmReg dst, VmReg src) noexcept {
        emit_op(OP_MOV_REG); emit_u8(static_cast<uint8_t>(dst)); emit_u8(static_cast<uint8_t>(src)); return *this;
    }
    constexpr ConstexprVmBuilder& add_reg(VmReg dst, VmReg src) noexcept {
        emit_op(OP_ADD_REG); emit_u8(static_cast<uint8_t>(dst)); emit_u8(static_cast<uint8_t>(src)); return *this;
    }
    constexpr ConstexprVmBuilder& add_imm(VmReg dst, uint64_t imm) noexcept {
        emit_op(OP_ADD_IMM); emit_u8(static_cast<uint8_t>(dst)); emit_u64(imm); return *this;
    }
    constexpr ConstexprVmBuilder& sub_reg(VmReg dst, VmReg src) noexcept {
        emit_op(OP_SUB_REG); emit_u8(static_cast<uint8_t>(dst)); emit_u8(static_cast<uint8_t>(src)); return *this;
    }
    constexpr ConstexprVmBuilder& sub_imm(VmReg dst, uint64_t imm) noexcept {
        emit_op(OP_SUB_IMM); emit_u8(static_cast<uint8_t>(dst)); emit_u64(imm); return *this;
    }
    constexpr ConstexprVmBuilder& imul_reg(VmReg dst, VmReg src) noexcept {
        emit_op(OP_IMUL_REG); emit_u8(static_cast<uint8_t>(dst)); emit_u8(static_cast<uint8_t>(src)); return *this;
    }
    constexpr ConstexprVmBuilder& xor_reg(VmReg dst, VmReg src) noexcept {
        emit_op(OP_XOR_REG); emit_u8(static_cast<uint8_t>(dst)); emit_u8(static_cast<uint8_t>(src)); return *this;
    }
    constexpr ConstexprVmBuilder& xor_imm(VmReg dst, uint64_t imm) noexcept {
        emit_op(OP_XOR_IMM); emit_u8(static_cast<uint8_t>(dst)); emit_u64(imm); return *this;
    }
    constexpr ConstexprVmBuilder& rol_imm(VmReg dst, uint8_t sh) noexcept {
        emit_op(OP_ROL_IMM); emit_u8(static_cast<uint8_t>(dst)); emit_u8(sh); return *this;
    }
    constexpr ConstexprVmBuilder& ror_imm(VmReg dst, uint8_t sh) noexcept {
        emit_op(OP_ROR_IMM); emit_u8(static_cast<uint8_t>(dst)); emit_u8(sh); return *this;
    }
    constexpr ConstexprVmBuilder& cmp_reg(VmReg lhs, VmReg rhs) noexcept {
        emit_op(OP_CMP_REG); emit_u8(static_cast<uint8_t>(lhs)); emit_u8(static_cast<uint8_t>(rhs)); return *this;
    }
    constexpr ConstexprVmBuilder& cmp_imm(VmReg lhs, uint64_t imm) noexcept {
        emit_op(OP_CMP_IMM); emit_u8(static_cast<uint8_t>(lhs)); emit_u64(imm); return *this;
    }
    constexpr ConstexprVmBuilder& push(VmReg src) noexcept {
        emit_op(OP_PUSH_REG); emit_u8(static_cast<uint8_t>(src)); return *this;
    }
    constexpr ConstexprVmBuilder& pop(VmReg dst) noexcept {
        emit_op(OP_POP_REG); emit_u8(static_cast<uint8_t>(dst)); return *this;
    }
    constexpr ConstexprVmBuilder& call_native(uint16_t slot_id, VmReg dst_ret) noexcept {
        emit_op(OP_CALL_NATIVE); emit_u16(slot_id); emit_u8(static_cast<uint8_t>(dst_ret)); return *this;
    }
    constexpr ConstexprVmBuilder& anti_debug_check() noexcept {
        emit_op(OP_ANTI_DEBUG_CHECK); return *this;
    }
    constexpr ConstexprVmBuilder& mba_add(VmReg dst, VmReg src) noexcept {
        emit_op(OP_MBA_ADD); emit_u8(static_cast<uint8_t>(dst)); emit_u8(static_cast<uint8_t>(src)); return *this;
    }
    constexpr ConstexprVmBuilder& mba_sub(VmReg dst, VmReg src) noexcept {
        emit_op(OP_MBA_SUB); emit_u8(static_cast<uint8_t>(dst)); emit_u8(static_cast<uint8_t>(src)); return *this;
    }
    constexpr ConstexprVmBuilder& mba_xor(VmReg dst, VmReg src) noexcept {
        emit_op(OP_MBA_XOR); emit_u8(static_cast<uint8_t>(dst)); emit_u8(static_cast<uint8_t>(src)); return *this;
    }
    constexpr ConstexprVmBuilder& gf2_mul(VmReg dst, VmReg src) noexcept {
        emit_op(OP_GF2_MUL); emit_u8(static_cast<uint8_t>(dst)); emit_u8(static_cast<uint8_t>(src)); return *this;
    }
    constexpr ConstexprVmBuilder& rotate_regs(uint8_t step = 3) noexcept {
        emit_op(OP_ROTATE_REGS); emit_u8(step); return *this;
    }
    constexpr ConstexprVmBuilder& state_matrix(uint8_t matrix_key) noexcept {
        emit_op(OP_STATE_MATRIX); emit_u8(matrix_key); return *this;
    }
    constexpr ConstexprVmBuilder& entangle_env(VmReg target_reg) noexcept {
        emit_op(OP_ENTANGLE_ENV); emit_u8(static_cast<uint8_t>(target_reg)); return *this;
    }
    constexpr ConstexprVmBuilder& ret() noexcept {
        emit_op(OP_RET); return *this;
    }

    constexpr ConstexprVmBuilder& label(uint8_t label_id) noexcept {
        emit_op(OP_SYNC_STATE);
        uint32_t target = static_cast<uint32_t>(size_);
        if (label_id < 16) {
            labels_[label_id] = target;
        }
        if (sync_count_ < 32) {
            sync_offsets_[sync_count_++] = target;
        }
        return *this;
    }

    constexpr ConstexprVmBuilder& jmp(uint8_t label_id) noexcept { return emit_branch(OP_JMP, label_id); }
    constexpr ConstexprVmBuilder& jz(uint8_t label_id) noexcept  { return emit_branch(OP_JZ,  label_id); }
    constexpr ConstexprVmBuilder& jnz(uint8_t label_id) noexcept { return emit_branch(OP_JNZ, label_id); }
    constexpr ConstexprVmBuilder& jg(uint8_t label_id) noexcept  { return emit_branch(OP_JG,  label_id); }
    constexpr ConstexprVmBuilder& jl(uint8_t label_id) noexcept  { return emit_branch(OP_JL,  label_id); }

    constexpr ConstexprVmProgram<MaxBytes> finalize() const noexcept {
        ConstexprVmProgram<MaxBytes> prog{};
        prog.seed = seed_;
        prog.size = size_;
        for (size_t i = 0; i < size_; ++i) {
            prog.bytecode[i] = raw_[i];
        }
        for (size_t f = 0; f < fixup_count_; ++f) {
            uint32_t target = labels_[fixups_[f].label_id & 15u];
            for (int b = 0; b < 4; ++b) {
                prog.bytecode[fixups_[f].offset + b] = static_cast<uint8_t>((target >> (b * 8)) & 0xFFu);
            }
        }
        uint64_t rolling_state = sync_rolling_state(seed_, 0);
        for (size_t idx = 0; idx < size_; ++idx) {
            for (size_t s = 0; s < sync_count_; ++s) {
                if (sync_offsets_[s] == idx) {
                    rolling_state = sync_rolling_state(seed_, idx);
                    break;
                }
            }
            uint8_t plain = prog.bytecode[idx];
            uint8_t ks    = rolling_stream_byte(rolling_state, idx, seed_);
            prog.bytecode[idx] = static_cast<uint8_t>(plain ^ ks);
            rolling_state = step_rolling_state(rolling_state, plain, idx, seed_);
        }
        prog.integrity_tag = compute_ciphertext_tag(prog.bytecode.data(), prog.size, seed_);
        return prog;
    }

private:
    struct FixupEntry {
        size_t  offset = 0;
        uint8_t label_id = 0;
    };

    constexpr void emit_u8(uint8_t v) noexcept {
        if (size_ < MaxBytes) raw_[size_++] = v;
    }
    constexpr void emit_op(LogicalOpcode op) noexcept {
        emit_u8(op_table_.logical_to_physical[static_cast<uint8_t>(op)]);
    }
    constexpr void emit_u16(uint16_t v) noexcept {
        emit_u8(static_cast<uint8_t>(v & 0xFFu));
        emit_u8(static_cast<uint8_t>((v >> 8) & 0xFFu));
    }
    constexpr void emit_u32(uint32_t v) noexcept {
        for (int i = 0; i < 4; ++i) emit_u8(static_cast<uint8_t>((v >> (i * 8)) & 0xFFu));
    }
    constexpr void emit_u64(uint64_t v) noexcept {
        for (int i = 0; i < 8; ++i) emit_u8(static_cast<uint8_t>((v >> (i * 8)) & 0xFFu));
    }
    constexpr ConstexprVmBuilder& emit_branch(LogicalOpcode op, uint8_t label_id) noexcept {
        emit_op(op);
        if (fixup_count_ < 32) {
            fixups_[fixup_count_++] = FixupEntry{size_, label_id};
        }
        emit_u32(0);
        return *this;
    }

    uint64_t                      seed_;
    PolymorphicOpcodeTable        op_table_;
    std::array<uint8_t, MaxBytes> raw_{};
    size_t                        size_ = 0;
    std::array<uint32_t, 16>      labels_{};
    std::array<FixupEntry, 32>    fixups_{};
    size_t                        fixup_count_ = 0;
    std::array<uint32_t, 32>      sync_offsets_{};
    size_t                        sync_count_ = 0;
};

class BytecodeBuilder {
public:
    explicit BytecodeBuilder(uint64_t seed = 0xD8B39A17E4C28F95ULL);

    BytecodeBuilder& nop();
    BytecodeBuilder& mov_imm(VmReg dst, uint64_t imm);
    BytecodeBuilder& mov_reg(VmReg dst, VmReg src);
    BytecodeBuilder& add_reg(VmReg dst, VmReg src);
    BytecodeBuilder& add_imm(VmReg dst, uint64_t imm);
    BytecodeBuilder& sub_reg(VmReg dst, VmReg src);
    BytecodeBuilder& sub_imm(VmReg dst, uint64_t imm);
    BytecodeBuilder& imul_reg(VmReg dst, VmReg src);
    BytecodeBuilder& xor_reg(VmReg dst, VmReg src);
    BytecodeBuilder& xor_imm(VmReg dst, uint64_t imm);
    BytecodeBuilder& and_reg(VmReg dst, VmReg src);
    BytecodeBuilder& or_reg(VmReg dst, VmReg src);
    BytecodeBuilder& shl_imm(VmReg dst, uint8_t shift);
    BytecodeBuilder& shr_imm(VmReg dst, uint8_t shift);
    BytecodeBuilder& rol_imm(VmReg dst, uint8_t shift);
    BytecodeBuilder& ror_imm(VmReg dst, uint8_t shift);
    BytecodeBuilder& not_reg(VmReg dst);
    BytecodeBuilder& neg_reg(VmReg dst);
    BytecodeBuilder& cmp_reg(VmReg lhs, VmReg rhs);
    BytecodeBuilder& cmp_imm(VmReg lhs, uint64_t imm);

    BytecodeBuilder& label(const std::string& name);
    BytecodeBuilder& jmp(const std::string& target_label);
    BytecodeBuilder& jz(const std::string& target_label);
    BytecodeBuilder& jnz(const std::string& target_label);
    BytecodeBuilder& jg(const std::string& target_label);
    BytecodeBuilder& jl(const std::string& target_label);

    BytecodeBuilder& push(VmReg src);
    BytecodeBuilder& pop(VmReg dst);
    BytecodeBuilder& load64(VmReg dst, VmReg addr_reg);
    BytecodeBuilder& store64(VmReg addr_reg, VmReg src);
    BytecodeBuilder& call_native(uint16_t slot_id, VmReg dst_ret);
    BytecodeBuilder& anti_debug_check();
    BytecodeBuilder& mba_add(VmReg dst, VmReg src);
    BytecodeBuilder& mba_sub(VmReg dst, VmReg src);
    BytecodeBuilder& mba_xor(VmReg dst, VmReg src);
    BytecodeBuilder& gf2_mul(VmReg dst, VmReg src);
    BytecodeBuilder& rotate_regs(uint8_t step = 3);
    BytecodeBuilder& state_matrix(uint8_t matrix_key);
    BytecodeBuilder& entangle_env(VmReg target_reg);
    BytecodeBuilder& ret();

    VmProgram finalize() const;

private:
    struct Fixup {
        size_t      offset;
        std::string label_name;
    };

    void emit_op(LogicalOpcode op);
    void emit_u8(uint8_t v);
    void emit_u16(uint16_t v);
    void emit_u32(uint32_t v);
    void emit_u64(uint64_t v);
    void emit_branch(LogicalOpcode op, const std::string& label_name);

    uint64_t                                  seed_;
    PolymorphicOpcodeTable                    op_table_;
    std::vector<uint8_t>                      raw_code_;
    std::unordered_map<std::string, uint32_t> labels_;
    std::vector<Fixup>                        fixups_;
    std::vector<uint32_t>                     sync_offsets_;
};

class VmEngine {
public:
    VmEngine() = default;

    void register_native(uint16_t slot_id, NativeCallback fn);

    bool execute(
        const VmProgram& program,
        VmContext& ctx,
        uint64_t* out_return_value = nullptr
    ) const noexcept;

    uint64_t run_WithArgs(
        const VmProgram& program,
        uint64_t r0 = 0,
        uint64_t r1 = 0,
        uint64_t r2 = 0,
        uint64_t r3 = 0,
        bool* out_ok = nullptr
    ) const noexcept;

private:
    std::unordered_map<uint16_t, NativeCallback> native_table_;
};

} // namespace vpack::vm
