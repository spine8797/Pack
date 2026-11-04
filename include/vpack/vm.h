#pragma once

#include "vpack/config.h"
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
    OP_RET,
    OP_MAX_COUNT
};

struct PolymorphicOpcodeTable {
    std::array<uint8_t, 256> logical_to_physical{};
    std::array<uint8_t, 256> physical_to_logical{};

    static PolymorphicOpcodeTable generate(uint64_t seed) noexcept;
};

struct VmProgram {
    uint64_t               seed = 0;
    uint64_t               integrity_tag = 0;
    std::vector<uint8_t>   bytecode;
};

using NativeCallback = uint64_t(*)(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3);

struct VmContext {
    std::array<uint64_t, REG_COUNT> regs{};
    std::vector<uint64_t>           stack;
    size_t                          ip = 0;
    uint32_t                        flags = FLAG_NONE;
    bool                            halted = false;
    bool                            tampered = false;

    VmContext(size_t stack_depth = 256) {
        stack.reserve(stack_depth);
    }
};

class BytecodeBuilder {
public:
    explicit BytecodeBuilder(uint64_t seed = 0x5341424C455F564DULL);

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

    uint64_t                                 seed_;
    PolymorphicOpcodeTable                   op_table_;
    std::vector<uint8_t>                     raw_code_;
    std::unordered_map<std::string, uint32_t> labels_;
    std::vector<Fixup>                       fixups_;
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
