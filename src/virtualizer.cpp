#include "vpack/virtualizer.h"
#include "vpack/anti_dump.h"
#include "vpack/anti_debug.h"
#include "vpack/crypto.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <intrin.h>
#include <cstring>
#include <unordered_set>

namespace vpack::virtualizer {

namespace {

constexpr size_t kMaxVirtualizedSlots = 16;

struct VirtualizedSlot {
    bool          occupied = false;
    LiftReport    report{};
    vm::VmProgram program{};
    vm::VmEngine  engine{};
};

VirtualizedSlot g_slots[kMaxVirtualizedSlots]{};

template <uint16_t Slot>
uint64_t vm_slot_thunk(uint64_t rcx_arg, uint64_t rdx_arg, uint64_t r8_arg, uint64_t r9_arg) noexcept {
    return execute_lifted_slot(Slot, rcx_arg, rdx_arg, r8_arg, r9_arg);
}

using ThunkFnPtr = uint64_t(*)(uint64_t, uint64_t, uint64_t, uint64_t) noexcept;

constexpr ThunkFnPtr kSlotThunks[kMaxVirtualizedSlots] = {
    &vm_slot_thunk<0>,  &vm_slot_thunk<1>,  &vm_slot_thunk<2>,  &vm_slot_thunk<3>,
    &vm_slot_thunk<4>,  &vm_slot_thunk<5>,  &vm_slot_thunk<6>,  &vm_slot_thunk<7>,
    &vm_slot_thunk<8>,  &vm_slot_thunk<9>,  &vm_slot_thunk<10>, &vm_slot_thunk<11>,
    &vm_slot_thunk<12>, &vm_slot_thunk<13>, &vm_slot_thunk<14>, &vm_slot_thunk<15>
};

struct DecodedInsn {
    size_t   offset         = 0;
    size_t   length         = 0;
    bool     has_66         = false;
    bool     has_rex        = false;
    bool     rex_w          = false;
    bool     rex_r          = false;
    bool     rex_x          = false;
    bool     rex_b          = false;
    bool     two_byte_0f    = false;
    uint8_t  opcode         = 0;
    bool     has_modrm      = false;
    uint8_t  mod            = 0;
    uint8_t  reg            = 0;
    uint8_t  rm             = 0;
    bool     has_sib        = false;
    bool     has_base       = false;
    bool     has_index      = false;
    bool     rip_relative   = false;
    uint8_t  scale_shift    = 0;
    uint8_t  index_reg      = 0;
    uint8_t  base_reg       = 0;
    int64_t  disp           = 0;
    uint64_t imm            = 0;
    bool     is_branch      = false;
    bool     is_uncond_jmp  = false;
    bool     is_ret         = false;
    uint8_t  jcc_cond       = 0;
    size_t   branch_target  = 0;
};

int32_t read_le_i32(const uint8_t* p) noexcept {
    uint32_t v = static_cast<uint32_t>(p[0]) |
                 (static_cast<uint32_t>(p[1]) << 8) |
                 (static_cast<uint32_t>(p[2]) << 16) |
                 (static_cast<uint32_t>(p[3]) << 24);
    return static_cast<int32_t>(v);
}

uint64_t read_le_u64(const uint8_t* p) noexcept {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= static_cast<uint64_t>(p[i]) << (i * 8);
    }
    return v;
}

bool decode_modrm_sib_disp(const uint8_t* code, size_t max_len, size_t& pos, DecodedInsn& insn) noexcept {
    if (pos >= max_len) return false;
    const uint8_t mrm = code[pos++];
    insn.has_modrm = true;
    insn.mod = (mrm >> 6) & 3u;
    insn.reg = static_cast<uint8_t>(((mrm >> 3) & 7u) | (insn.rex_r ? 8u : 0u));
    const uint8_t rm_low = mrm & 7u;
    insn.rm  = static_cast<uint8_t>(rm_low | (insn.rex_b ? 8u : 0u));

    if (insn.mod == 3u) {
        return true;
    }

    if (rm_low == 4u) {
        if (pos >= max_len) return false;
        const uint8_t sib = code[pos++];
        insn.has_sib     = true;
        insn.scale_shift = (sib >> 6) & 3u;
        const uint8_t idx_low  = (sib >> 3) & 7u;
        const uint8_t base_low = sib & 7u;
        insn.index_reg = static_cast<uint8_t>(idx_low | (insn.rex_x ? 8u : 0u));
        insn.base_reg  = static_cast<uint8_t>(base_low | (insn.rex_b ? 8u : 0u));
        insn.has_index = (insn.index_reg != 4u); // RSP (4) means no index; R12 (12) is valid

        if (insn.mod == 0u && base_low == 5u) {
            insn.has_base = false;
            if (pos + 4 > max_len) return false;
            insn.disp = static_cast<int64_t>(read_le_i32(code + pos));
            pos += 4;
            return true;
        }
        insn.has_base = true;
    } else if (insn.mod == 0u && rm_low == 5u) {
        insn.rip_relative = true;
        if (pos + 4 > max_len) return false;
        insn.disp = static_cast<int64_t>(read_le_i32(code + pos));
        pos += 4;
        return true;
    } else {
        insn.has_base = true;
        insn.base_reg = insn.rm;
    }

    if (insn.mod == 1u) {
        if (pos >= max_len) return false;
        insn.disp = static_cast<int64_t>(static_cast<int8_t>(code[pos++]));
    } else if (insn.mod == 2u) {
        if (pos + 4 > max_len) return false;
        insn.disp = static_cast<int64_t>(read_le_i32(code + pos));
        pos += 4;
    }
    return true;
}

bool decode_one_x64(const uint8_t* code, size_t max_len, size_t offset, DecodedInsn& out) noexcept {
    out = DecodedInsn{};
    out.offset = offset;
    size_t pos = offset;

    // 1. Parse prefixes (0x66, 0xF0, 0xF2, 0xF3, 0x2E, 0x3E, and REX 0x40..0x4F)
    while (pos < max_len) {
        const uint8_t b = code[pos];
        if (b == 0x66) {
            out.has_66 = true;
            ++pos;
        } else if (b == 0x2E || b == 0x3E || b == 0xF0 || b == 0xF2 || b == 0xF3) {
            ++pos;
        } else if (b >= 0x40 && b <= 0x4F) {
            out.has_rex = true;
            out.rex_w   = (b & 0x08u) != 0;
            out.rex_r   = (b & 0x04u) != 0;
            out.rex_x   = (b & 0x02u) != 0;
            out.rex_b   = (b & 0x01u) != 0;
            ++pos;
            break; // REX must immediately precede the opcode
        } else {
            break;
        }
    }

    if (pos >= max_len) return false;
    uint8_t op = code[pos++];

    if (op == 0x0F) {
        if (pos >= max_len) return false;
        out.two_byte_0f = true;
        op = code[pos++];
        out.opcode = op;

        // Multi-byte NOP: 0F 1F /0
        if (op == 0x1F) {
            if (!decode_modrm_sib_disp(code, max_len, pos, out)) return false;
            out.length = pos - offset;
            return true;
        }
        // Near Jcc: 0F 80..8F cd
        if (op >= 0x80 && op <= 0x8F) {
            if (pos + 4 > max_len) return false;
            int32_t rel = read_le_i32(code + pos);
            pos += 4;
            out.is_branch     = true;
            out.jcc_cond      = static_cast<uint8_t>(op & 0x0Fu);
            out.length        = pos - offset;
            out.branch_target = static_cast<size_t>(static_cast<intptr_t>(pos) + rel);
            return true;
        }
        // IMUL r64, r/m64 (0F AF /r), MOVZX (0F B6, 0F B7), MOVSX (0F BE, 0F BF), CMOVcc (0F 40..4F), SETcc (0F 90..9F)
        if (op == 0xAF || op == 0xB6 || op == 0xB7 || op == 0xBE || op == 0xBF ||
            (op >= 0x40 && op <= 0x4F) || (op >= 0x90 && op <= 0x9F)) {
            if (!decode_modrm_sib_disp(code, max_len, pos, out)) return false;
            out.length = pos - offset;
            return true;
        }
        return false;
    }

    out.opcode = op;

    // Single-byte NOP (0x90) or RET (0xC3)
    if (op == 0x90) {
        out.length = pos - offset;
        return true;
    }
    if (op == 0xC3) {
        out.is_ret = true;
        out.length = pos - offset;
        return true;
    }

    // PUSH r64 (50..57) / POP r64 (58..5F)
    if (op >= 0x50 && op <= 0x5F) {
        out.rm     = static_cast<uint8_t>((op & 7u) | (out.rex_b ? 8u : 0u));
        out.length = pos - offset;
        return true;
    }

    // Short Jcc (70..7F cb) or Short JMP (EB cb)
    if ((op >= 0x70 && op <= 0x7F) || op == 0xEB) {
        if (pos >= max_len) return false;
        int8_t rel = static_cast<int8_t>(code[pos++]);
        out.is_branch     = true;
        out.is_uncond_jmp = (op == 0xEB);
        out.jcc_cond      = static_cast<uint8_t>(op & 0x0Fu);
        out.length        = pos - offset;
        out.branch_target = static_cast<size_t>(static_cast<intptr_t>(pos) + rel);
        return true;
    }

    // Near JMP (E9 cd)
    if (op == 0xE9) {
        if (pos + 4 > max_len) return false;
        int32_t rel = read_le_i32(code + pos);
        pos += 4;
        out.is_branch     = true;
        out.is_uncond_jmp = true;
        out.length        = pos - offset;
        out.branch_target = static_cast<size_t>(static_cast<intptr_t>(pos) + rel);
        return true;
    }

    // MOV reg, imm64/imm32 (B8..BF)
    if (op >= 0xB8 && op <= 0xBF) {
        out.rm = static_cast<uint8_t>((op & 7u) | (out.rex_b ? 8u : 0u));
        if (out.rex_w) {
            if (pos + 8 > max_len) return false;
            out.imm = read_le_u64(code + pos);
            pos += 8;
        } else {
            if (pos + 4 > max_len) return false;
            out.imm = static_cast<uint64_t>(static_cast<uint32_t>(read_le_i32(code + pos)));
            pos += 4;
        }
        out.length = pos - offset;
        return true;
    }

    // Accumulator RAX/EAX immediate ops: ADD(05), OR(0D), AND(25), SUB(2D), XOR(35), CMP(3D), TEST(A9)
    if (op == 0x05 || op == 0x0D || op == 0x25 || op == 0x2D || op == 0x35 || op == 0x3D || op == 0xA9) {
        if (pos + 4 > max_len) return false;
        int32_t imm32 = read_le_i32(code + pos);
        pos += 4;
        out.imm    = out.rex_w ? static_cast<uint64_t>(static_cast<int64_t>(imm32))
                               : static_cast<uint64_t>(static_cast<uint32_t>(imm32));
        out.length = pos - offset;
        return true;
    }
    if (op == 0xA8) {
        if (pos >= max_len) return false;
        out.imm    = code[pos++];
        out.length = pos - offset;
        return true;
    }

    // Standard ModR/M instructions (no immediate)
    if (op == 0x89 || op == 0x8B || op == 0x8D || op == 0x63 ||
        op == 0x01 || op == 0x03 || op == 0x09 || op == 0x0B ||
        op == 0x21 || op == 0x23 || op == 0x29 || op == 0x2B ||
        op == 0x31 || op == 0x33 || op == 0x39 || op == 0x3B ||
        op == 0x84 || op == 0x85 || op == 0xD1 || op == 0xD3 || op == 0xFF) {
        if (!decode_modrm_sib_disp(code, max_len, pos, out)) return false;
        out.length = pos - offset;
        return true;
    }

    // ModR/M + imm8: 83 /0..7 ib, C1 /0..7 ib, 6B /r ib, C6 /0 ib
    if (op == 0x83 || op == 0xC1 || op == 0x6B || op == 0xC6) {
        if (!decode_modrm_sib_disp(code, max_len, pos, out)) return false;
        if (pos >= max_len) return false;
        int8_t imm8 = static_cast<int8_t>(code[pos++]);
        if (op == 0xC1 || op == 0xC6) {
            out.imm = static_cast<uint8_t>(imm8);
        } else {
            out.imm = out.rex_w ? static_cast<uint64_t>(static_cast<int64_t>(imm8))
                                : static_cast<uint64_t>(static_cast<uint32_t>(static_cast<int32_t>(imm8)));
        }
        out.length = pos - offset;
        return true;
    }

    // ModR/M + imm32: 81 /0..7 id, C7 /0 id, 69 /r id
    if (op == 0x81 || op == 0xC7 || op == 0x69) {
        if (!decode_modrm_sib_disp(code, max_len, pos, out)) return false;
        if (pos + 4 > max_len) return false;
        int32_t imm32 = read_le_i32(code + pos);
        pos += 4;
        out.imm    = out.rex_w ? static_cast<uint64_t>(static_cast<int64_t>(imm32))
                               : static_cast<uint64_t>(static_cast<uint32_t>(imm32));
        out.length = pos - offset;
        return true;
    }

    // Group 3 Unary (F6 / F7): /0 = TEST imm, /2 = NOT, /3 = NEG, /4 = MUL, /5 = IMUL
    if (op == 0xF6 || op == 0xF7) {
        if (!decode_modrm_sib_disp(code, max_len, pos, out)) return false;
        const uint8_t subop = out.reg & 7u;
        if (subop == 0u || subop == 1u) {
            if (op == 0xF6) {
                if (pos >= max_len) return false;
                out.imm = code[pos++];
            } else {
                if (pos + 4 > max_len) return false;
                int32_t imm32 = read_le_i32(code + pos);
                pos += 4;
                out.imm = out.rex_w ? static_cast<uint64_t>(static_cast<int64_t>(imm32))
                                    : static_cast<uint64_t>(static_cast<uint32_t>(imm32));
            }
        }
        out.length = pos - offset;
        return true;
    }

    return false;
}

// Emits effective address calculation into `dst_reg` using Non-Linear MBA micro-ops
void emit_effective_address(
    vm::BytecodeBuilder& b,
    const uint8_t*       fn_base,
    const DecodedInsn&   insn,
    vm::VmReg            dst_reg
) {
    using namespace vpack::vm;
    if (insn.rip_relative) {
        const uint64_t target_addr = reinterpret_cast<uint64_t>(fn_base + insn.offset + insn.length) +
                                     static_cast<uint64_t>(insn.disp);
        b.mov_imm(dst_reg, target_addr);
        return;
    }

    bool initialized = false;
    if (insn.has_base) {
        b.mov_reg(dst_reg, static_cast<VmReg>(insn.base_reg));
        initialized = true;
    }

    if (insn.has_index) {
        if (!initialized) {
            b.mov_reg(dst_reg, static_cast<VmReg>(insn.index_reg));
            if (insn.scale_shift > 0) {
                b.shl_imm(dst_reg, insn.scale_shift);
            }
            initialized = true;
        } else {
            b.mov_reg(VTMP1, static_cast<VmReg>(insn.index_reg));
            if (insn.scale_shift > 0) {
                b.shl_imm(VTMP1, insn.scale_shift);
            }
            b.mba_add(dst_reg, VTMP1);
        }
    }

    if (insn.disp != 0 || !initialized) {
        if (!initialized) {
            b.mov_imm(dst_reg, static_cast<uint64_t>(insn.disp));
        } else {
            b.mov_imm(VTMP1, static_cast<uint64_t>(insn.disp));
            b.mba_add(dst_reg, VTMP1);
        }
    }
}

vm::VmReg load_rm_operand(
    vm::BytecodeBuilder& b,
    const uint8_t*       fn_base,
    const DecodedInsn&   insn,
    vm::VmReg            scratch_reg = vm::VTMP0
) {
    using namespace vpack::vm;
    if (insn.mod == 3u) {
        return static_cast<VmReg>(insn.rm);
    }
    emit_effective_address(b, fn_base, insn, scratch_reg);
    b.load64(scratch_reg, scratch_reg);
    return scratch_reg;
}

void store_rm_operand(
    vm::BytecodeBuilder& b,
    const uint8_t*       fn_base,
    const DecodedInsn&   insn,
    vm::VmReg            val_reg,
    bool                 zero_ext_32
) {
    using namespace vpack::vm;
    if (zero_ext_32) {
        b.movzx32(val_reg, val_reg);
    }
    if (insn.mod == 3u) {
        const auto dst = static_cast<VmReg>(insn.rm);
        if (dst != val_reg) {
            b.mov_reg(dst, val_reg);
        }
        return;
    }
    emit_effective_address(b, fn_base, insn, VTMP0);
    b.store64(VTMP0, val_reg);
}

void emit_jcc_by_code(vm::BytecodeBuilder& b, uint8_t cond, const std::string& lbl) {
    switch (cond & 0x0Fu) {
        case 0x2: b.jb(lbl);  break; // JB / JC / JNAE
        case 0x3: b.jae(lbl); break; // JAE / JNB / JNC
        case 0x4: b.jz(lbl);  break; // JE / JZ
        case 0x5: b.jnz(lbl); break; // JNE / JNZ
        case 0x6: b.jbe(lbl); break; // JBE / JNA
        case 0x7: b.ja(lbl);  break; // JA / JNBE
        case 0xC: b.jl(lbl);  break; // JL / JNGE
        case 0xD: b.jge(lbl); break; // JGE / JNL
        case 0xE: b.jle(lbl); break; // JLE / JNG
        case 0xF: b.jg(lbl);  break; // JG / JNLE
        default:  b.jnz(lbl); break;
    }
}

} // namespace

bool lift_x64_function(
    const uint8_t*   fn_bytes,
    size_t           max_scan_bytes,
    uint64_t         vm_seed,
    vm::VmProgram&   out_program,
    size_t*          out_native_size,
    size_t*          out_decoded_insns
) noexcept {
    if (!fn_bytes || max_scan_bytes < 16) return false;

    std::vector<DecodedInsn> insns;
    insns.reserve(128);
    std::unordered_set<size_t> branch_targets;

    size_t offset            = 0;
    size_t max_branch_target = 0;
    bool   found_end         = false;

    while (offset < max_scan_bytes) {
        DecodedInsn insn{};
        if (!decode_one_x64(fn_bytes, max_scan_bytes, offset, insn) || insn.length == 0) {
            return false;
        }
        insns.push_back(insn);

        if (insn.is_branch) {
            if (insn.branch_target >= max_scan_bytes) {
                return false; // External tail-call jump outside scan window
            }
            branch_targets.insert(insn.branch_target);
            if (insn.branch_target > max_branch_target) {
                max_branch_target = insn.branch_target;
            }
        }

        offset += insn.length;

        if (insn.is_ret && offset > max_branch_target) {
            found_end = true;
            break;
        }
        if (insn.is_uncond_jmp && insn.branch_target < offset && offset > max_branch_target) {
            found_end = true;
            break;
        }
    }

    if (!found_end || offset < 12) {
        return false;
    }

    using namespace vpack::vm;
    const uint64_t effective_seed = (vm_seed != 0)
        ? vm_seed
        : (__rdtsc() ^ reinterpret_cast<uint64_t>(fn_bytes) ^ 0xA983C1E59F27B4D3ULL);

    BytecodeBuilder b(effective_seed);
    b.anti_debug_check()
     .entangle_env(R1);

    for (size_t idx = 0; idx < insns.size(); ++idx) {
        const auto& insn = insns[idx];
        if (branch_targets.count(insn.offset)) {
            b.label("L_" + std::to_string(insn.offset));
            b.rotate_regs(static_cast<uint8_t>((insn.offset & 7u) | 1u));
        }

        const bool zext32 = !insn.rex_w;

        if (insn.two_byte_0f) {
            const uint8_t op = insn.opcode;
            if (op == 0x1F) {
                b.nop();
            } else if (op >= 0x80 && op <= 0x8F) {
                emit_jcc_by_code(b, op & 0x0Fu, "L_" + std::to_string(insn.branch_target));
            } else if (op == 0xAF) {
                // imul reg, r/m
                const auto dst = static_cast<VmReg>(insn.reg);
                const VmReg src = load_rm_operand(b, fn_bytes, insn, VTMP0);
                b.imul_reg(dst, src);
                if (zext32) b.movzx32(dst, dst);
            } else if (op == 0xB6) {
                // movzx reg, r/m8
                const auto dst = static_cast<VmReg>(insn.reg);
                const VmReg src = load_rm_operand(b, fn_bytes, insn, VTMP0);
                b.mov_reg(dst, src)
                 .mov_imm(VTMP1, 0xFFULL)
                 .and_reg(dst, VTMP1);
            } else if (op == 0xB7) {
                // movzx reg, r/m16
                const auto dst = static_cast<VmReg>(insn.reg);
                const VmReg src = load_rm_operand(b, fn_bytes, insn, VTMP0);
                b.mov_reg(dst, src)
                 .mov_imm(VTMP1, 0xFFFFULL)
                 .and_reg(dst, VTMP1);
            } else if (op >= 0x40 && op <= 0x4F) {
                // cmovcc reg, r/m -> branch around mov_reg using inverted condition (cond ^ 1)
                const auto dst = static_cast<VmReg>(insn.reg);
                const VmReg src = load_rm_operand(b, fn_bytes, insn, VTMP0);
                const std::string skip_lbl = "CMOV_" + std::to_string(idx);
                emit_jcc_by_code(b, (op & 0x0Fu) ^ 1u, skip_lbl);
                b.mov_reg(dst, src);
                b.label(skip_lbl);
                if (zext32) b.movzx32(dst, dst);
            }
            continue;
        }

        const uint8_t op = insn.opcode;
        if (op == 0x90) {
            b.nop();
        } else if (op == 0xC3) {
            b.anti_debug_check()
             .ret();
        } else if (op >= 0x50 && op <= 0x57) {
            b.push(static_cast<VmReg>(insn.rm));
        } else if (op >= 0x58 && op <= 0x5F) {
            b.pop(static_cast<VmReg>(insn.rm));
        } else if (op == 0xEB || op == 0xE9) {
            b.jmp("L_" + std::to_string(insn.branch_target));
        } else if (op >= 0x70 && op <= 0x7F) {
            emit_jcc_by_code(b, insn.jcc_cond, "L_" + std::to_string(insn.branch_target));
        } else if (op >= 0xB8 && op <= 0xBF) {
            b.mov_imm(static_cast<VmReg>(insn.rm), insn.imm);
        } else if (op == 0x89) {
            // mov r/m, reg
            const auto src = static_cast<VmReg>(insn.reg);
            if (insn.mod == 3u) {
                const auto dst = static_cast<VmReg>(insn.rm);
                b.mov_reg(dst, src);
                if (zext32) b.movzx32(dst, dst);
            } else {
                b.mov_reg(VTMP1, src);
                store_rm_operand(b, fn_bytes, insn, VTMP1, zext32);
            }
        } else if (op == 0x8B) {
            // mov reg, r/m
            const auto dst = static_cast<VmReg>(insn.reg);
            const VmReg src = load_rm_operand(b, fn_bytes, insn, VTMP0);
            b.mov_reg(dst, src);
            if (zext32) b.movzx32(dst, dst);
        } else if (op == 0xC7) {
            // mov r/m, imm32
            b.mov_imm(VTMP1, insn.imm);
            store_rm_operand(b, fn_bytes, insn, VTMP1, zext32);
        } else if (op == 0x63) {
            // movsxd r64, r/m32
            const auto dst = static_cast<VmReg>(insn.reg);
            const VmReg src = load_rm_operand(b, fn_bytes, insn, VTMP0);
            b.mov_reg(dst, src)
             .shl_imm(dst, 32)
             .sar_imm(dst, 32);
        } else if (op == 0x8D) {
            // lea reg, m -> decomposed into Non-Linear MBA address micro-ops
            const auto dst = static_cast<VmReg>(insn.reg);
            emit_effective_address(b, fn_bytes, insn, VTMP0);
            b.mov_reg(dst, VTMP0);
            if (zext32) b.movzx32(dst, dst);
        } else if (op == 0x01 || op == 0x03 || op == 0x29 || op == 0x2B ||
                   op == 0x31 || op == 0x33 || op == 0x21 || op == 0x23 ||
                   op == 0x09 || op == 0x0B) {
            const bool dir_rm_to_reg = (op & 0x02u) != 0;
            const uint8_t base_op    = static_cast<uint8_t>(op & ~0x03u);
            const auto reg_op        = static_cast<VmReg>(insn.reg);

            if (dir_rm_to_reg) {
                const VmReg src = load_rm_operand(b, fn_bytes, insn, VTMP0);
                if (base_op == 0x00)      b.mba_add(reg_op, src);
                else if (base_op == 0x28) b.mba_sub(reg_op, src);
                else if (base_op == 0x30) b.mba_xor(reg_op, src);
                else if (base_op == 0x20) b.and_reg(reg_op, src);
                else if (base_op == 0x08) b.or_reg(reg_op, src);
                if (zext32) b.movzx32(reg_op, reg_op);
            } else {
                const VmReg cur = load_rm_operand(b, fn_bytes, insn, VTMP1);
                if (base_op == 0x00)      b.mba_add(cur, reg_op);
                else if (base_op == 0x28) b.mba_sub(cur, reg_op);
                else if (base_op == 0x30) b.mba_xor(cur, reg_op);
                else if (base_op == 0x20) b.and_reg(cur, reg_op);
                else if (base_op == 0x08) b.or_reg(cur, reg_op);
                store_rm_operand(b, fn_bytes, insn, cur, zext32);
            }
        } else if (op == 0x39 || op == 0x3B) {
            // cmp r/m, reg (39) or cmp reg, r/m (3B)
            VmReg lhs = (op == 0x39) ? load_rm_operand(b, fn_bytes, insn, VTMP0)
                                     : static_cast<VmReg>(insn.reg);
            VmReg rhs = (op == 0x39) ? static_cast<VmReg>(insn.reg)
                                     : load_rm_operand(b, fn_bytes, insn, VTMP0);
            if (zext32) {
                b.mov_reg(VTMP0, lhs).shl_imm(VTMP0, 32).sar_imm(VTMP0, 32);
                b.mov_reg(VTMP1, rhs).shl_imm(VTMP1, 32).sar_imm(VTMP1, 32);
                b.cmp_reg(VTMP0, VTMP1);
            } else {
                b.cmp_reg(lhs, rhs);
            }
        } else if (op == 0x85 || op == 0x84) {
            // test r/m, reg
            const VmReg lhs = load_rm_operand(b, fn_bytes, insn, VTMP0);
            const auto  rhs = static_cast<VmReg>(insn.reg);
            b.mov_reg(VTMP1, lhs)
             .and_reg(VTMP1, rhs);
            if (op == 0x84) {
                b.mov_imm(VTMP0, 0xFFULL).and_reg(VTMP1, VTMP0);
            } else if (zext32) {
                b.shl_imm(VTMP1, 32).sar_imm(VTMP1, 32);
            }
            b.cmp_imm(VTMP1, 0);
        } else if (op == 0x81 || op == 0x83) {
            // ALU Group 1 with immediate: /0=ADD, /1=OR, /4=AND, /5=SUB, /6=XOR, /7=CMP
            const uint8_t subop = insn.reg & 7u;
            const VmReg   cur   = load_rm_operand(b, fn_bytes, insn, VTMP1);
            if (subop == 7u) {
                if (zext32) {
                    const uint64_t sext_imm = static_cast<uint64_t>(
                        static_cast<int64_t>(static_cast<int32_t>(insn.imm))
                    );
                    b.mov_reg(VTMP0, cur).shl_imm(VTMP0, 32).sar_imm(VTMP0, 32);
                    b.cmp_imm(VTMP0, sext_imm);
                } else {
                    b.cmp_imm(cur, insn.imm);
                }
            } else {
                b.mov_imm(VTMP0, insn.imm);
                if (subop == 0u)      b.mba_add(cur, VTMP0);
                else if (subop == 1u) b.or_reg(cur, VTMP0);
                else if (subop == 4u) b.and_reg(cur, VTMP0);
                else if (subop == 5u) b.mba_sub(cur, VTMP0);
                else if (subop == 6u) b.mba_xor(cur, VTMP0);
                store_rm_operand(b, fn_bytes, insn, cur, zext32);
            }
        } else if (op == 0x05 || op == 0x0D || op == 0x25 || op == 0x2D || op == 0x35 || op == 0x3D || op == 0xA9 || op == 0xA8) {
            if (op == 0x3D) {
                if (zext32) {
                    const uint64_t sext_imm = static_cast<uint64_t>(
                        static_cast<int64_t>(static_cast<int32_t>(insn.imm))
                    );
                    b.mov_reg(VTMP0, R0).shl_imm(VTMP0, 32).sar_imm(VTMP0, 32);
                    b.cmp_imm(VTMP0, sext_imm);
                } else {
                    b.cmp_imm(R0, insn.imm);
                }
            } else if (op == 0xA9 || op == 0xA8) {
                b.mov_reg(VTMP1, R0)
                 .mov_imm(VTMP0, insn.imm)
                 .and_reg(VTMP1, VTMP0);
                if (zext32 && op == 0xA9) {
                    b.shl_imm(VTMP1, 32).sar_imm(VTMP1, 32);
                }
                b.cmp_imm(VTMP1, 0);
            } else {
                b.mov_imm(VTMP0, insn.imm);
                if (op == 0x05)      b.mba_add(R0, VTMP0);
                else if (op == 0x0D) b.or_reg(R0, VTMP0);
                else if (op == 0x25) b.and_reg(R0, VTMP0);
                else if (op == 0x2D) b.mba_sub(R0, VTMP0);
                else if (op == 0x35) b.mba_xor(R0, VTMP0);
                if (zext32) b.movzx32(R0, R0);
            }
        } else if (op == 0x69 || op == 0x6B) {
            // imul reg, r/m, imm
            const auto dst = static_cast<VmReg>(insn.reg);
            const VmReg src = load_rm_operand(b, fn_bytes, insn, VTMP0);
            b.mov_reg(dst, src)
             .mov_imm(VTMP1, insn.imm)
             .imul_reg(dst, VTMP1);
            if (zext32) b.movzx32(dst, dst);
        } else if (op == 0xC1 || op == 0xD1 || op == 0xD3) {
            // Shifts & Rotates: /0=ROL, /1=ROR, /4=SHL, /5=SHR, /7=SAR
            const uint8_t subop = insn.reg & 7u;
            const VmReg   cur   = load_rm_operand(b, fn_bytes, insn, VTMP1);
            if (op == 0xD3) {
                if (subop == 4u)      b.shl_reg(cur, R1);
                else if (subop == 5u) {
                    if (zext32) b.movzx32(cur, cur);
                    b.shr_reg(cur, R1);
                }
            } else {
                const uint8_t sh = (op == 0xD1) ? 1u : static_cast<uint8_t>(insn.imm & 63u);
                if (subop == 0u)      b.rol_imm(cur, sh);
                else if (subop == 1u) b.ror_imm(cur, sh);
                else if (subop == 4u) b.shl_imm(cur, sh);
                else if (subop == 5u) {
                    if (zext32) b.movzx32(cur, cur);
                    b.shr_imm(cur, sh);
                } else if (subop == 7u) {
                    if (zext32) {
                        b.shl_imm(cur, 32).sar_imm(cur, static_cast<uint8_t>(32u + (sh & 31u)));
                    } else {
                        b.sar_imm(cur, sh);
                    }
                }
            }
            store_rm_operand(b, fn_bytes, insn, cur, zext32);
        } else if (op == 0xF6 || op == 0xF7) {
            const uint8_t subop = insn.reg & 7u;
            const VmReg   cur   = load_rm_operand(b, fn_bytes, insn, VTMP1);
            if (subop == 0u || subop == 1u) {
                b.mov_reg(VTMP1, cur)
                 .mov_imm(VTMP0, insn.imm)
                 .and_reg(VTMP1, VTMP0);
                if (zext32 && op == 0xF7) {
                    b.shl_imm(VTMP1, 32).sar_imm(VTMP1, 32);
                }
                b.cmp_imm(VTMP1, 0);
            } else if (subop == 2u) {
                b.not_reg(cur);
                store_rm_operand(b, fn_bytes, insn, cur, zext32);
            } else if (subop == 3u) {
                b.neg_reg(cur);
                store_rm_operand(b, fn_bytes, insn, cur, zext32);
            } else if (subop == 4u || subop == 5u) {
                b.imul_reg(R0, cur);
                if (zext32) b.movzx32(R0, R0);
            }
        } else if (op == 0xFF) {
            const uint8_t subop = insn.reg & 7u;
            const VmReg   cur   = load_rm_operand(b, fn_bytes, insn, VTMP1);
            b.mov_imm(VTMP0, 1ULL);
            if (subop == 0u)      b.mba_add(cur, VTMP0);
            else if (subop == 1u) b.mba_sub(cur, VTMP0);
            store_rm_operand(b, fn_bytes, insn, cur, zext32);
        }
    }

    out_program = b.finalize();
    if (out_program.bytecode.empty()) {
        return false;
    }
    if (out_native_size)   *out_native_size   = offset;
    if (out_decoded_insns) *out_decoded_insns = insns.size();
    return true;
}

uint64_t execute_lifted_slot(
    uint16_t slot_id,
    uint64_t rcx_arg,
    uint64_t rdx_arg,
    uint64_t r8_arg,
    uint64_t r9_arg
) noexcept {
    if (slot_id >= kMaxVirtualizedSlots || !g_slots[slot_id].occupied) {
        return 0;
    }
    const auto& slot = g_slots[slot_id];
    return slot.engine.run_x64_abi(slot.program, rcx_arg, rdx_arg, r8_arg, r9_arg, nullptr);
}

LiftReport virtualize_and_shred(
    void*    fn_address,
    size_t   max_scan_bytes,
    uint64_t custom_seed
) noexcept {
    LiftReport rep{};
    rep.function_address = fn_address;
    if (!fn_address) return rep;

    // Find a free slot
    uint16_t slot_id = 0xFFFFu;
    for (uint16_t i = 0; i < kMaxVirtualizedSlots; ++i) {
        if (g_slots[i].occupied && g_slots[i].report.function_address == fn_address) {
            return g_slots[i].report;
        }
        if (!g_slots[i].occupied && slot_id == 0xFFFFu) {
            slot_id = i;
        }
    }
    if (slot_id == 0xFFFFu) return rep;

    auto* target_fn = static_cast<uint8_t*>(fn_address);
    vm::VmProgram prog{};
    size_t native_size   = 0;
    size_t decoded_insns = 0;

    // Phase 1: Unlock .vcode as RX via JitSectionGuard, decode & lift x86_64 instructions,
    // and verify mathematical equivalence between native_fn and the lifted VmProgram!
    {
        antidump::JitSectionGuard rx_guard;
        if (!lift_x64_function(target_fn, max_scan_bytes, custom_seed, prog, &native_size, &decoded_insns) ||
            native_size < 14) {
            return rep;
        }

        using GenericX64Fn = uint64_t(*)(uint64_t, uint64_t, uint64_t, uint64_t);
        auto native_fn = reinterpret_cast<GenericX64Fn>(target_fn);
        const uint64_t expected_out = native_fn(0x1001A5A5ULL, 0x9988776655443322ULL, 0ULL, 0ULL);

        vm::VmEngine test_engine;
        bool vm_ok = false;
        const uint64_t lifted_out = test_engine.run_x64_abi(
            prog, 0x1001A5A5ULL, 0x9988776655443322ULL, 0ULL, 0ULL, &vm_ok
        );
        if (!vm_ok || lifted_out != expected_out) {
            return rep;
        }
    }

    auto write_trampoline_and_shred = [&](uint8_t* fn_ptr) -> bool {
        // Write 12-byte VM Entry Trampoline at fn_ptr[0..11]:
        //   48 B8 <8-byte address of kSlotThunks[slot_id]>  (movabs rax, imm64)
        //   FF E0                                           (jmp rax)
        const uint64_t thunk_addr = reinterpret_cast<uint64_t>(
            reinterpret_cast<void*>(kSlotThunks[slot_id])
        );
        fn_ptr[0] = 0x48;
        fn_ptr[1] = 0xB8;
        for (int b = 0; b < 8; ++b) {
            fn_ptr[2 + b] = static_cast<uint8_t>((thunk_addr >> (b * 8)) & 0xFFu);
        }
        fn_ptr[10] = 0xFF;
        fn_ptr[11] = 0xE0;

        // Place an immediate UD2 trap (0F 0B) at offset 12..13 and shred all remaining
        // native x86_64 instructions with high-entropy polymorphic noise!
        fn_ptr[12] = 0x0F;
        fn_ptr[13] = 0x0B;
        uint64_t noise = prog.seed ^ __rdtsc() ^ 0xD8B39A17E4C28F95ULL;
        for (size_t i = 14; i < native_size; ++i) {
            noise = crypto::poly_permute_64(noise, i ^ 0x9E3779B97F4A7C15ULL);
            fn_ptr[i] = static_cast<uint8_t>((noise ^ (noise >> 23)) & 0xFFu);
        }
        return true;
    };

    // Phase 2: Permanently shred native x86_64 instructions in RAM and install VM entry thunk
    bool shredded = false;
    if (antidump::is_vcode_jit_active()) {
        shredded = antidump::modify_vcode_in_vault([&](uint8_t* vcode_base, size_t vcode_size) -> bool {
            if (target_fn >= vcode_base && target_fn + native_size <= vcode_base + vcode_size) {
                return write_trampoline_and_shred(target_fn);
            }
            return false;
        });
    }

    if (!shredded) {
        using FnVirtualProtect = BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD);
        static auto fn_vp = VPACK_IMPORT(FnVirtualProtect, "kernel32.dll", "VirtualProtect");
        DWORD old_prot = 0;
        if (fn_vp.get() && fn_vp(target_fn, native_size, PAGE_READWRITE, &old_prot)) {
            shredded = write_trampoline_and_shred(target_fn);
            DWORD dummy = 0;
            fn_vp(target_fn, native_size, old_prot, &dummy);
            FlushInstructionCache(GetCurrentProcess(), target_fn, native_size);
        }
    }

    if (shredded) {
        rep.success          = true;
        rep.native_code_size = native_size;
        rep.decoded_insns    = decoded_insns;
        rep.vm_bytecode_size = prog.bytecode.size();
        rep.slot_id          = slot_id;
        rep.vm_seed          = prog.seed;
        rep.native_shredded  = true;

        g_slots[slot_id].occupied = true;
        g_slots[slot_id].report   = rep;
        g_slots[slot_id].program  = std::move(prog);
    }

    return rep;
}

bool is_function_virtualized(const void* fn_address, LiftReport* out_report) noexcept {
    for (uint16_t i = 0; i < kMaxVirtualizedSlots; ++i) {
        if (g_slots[i].occupied && g_slots[i].report.function_address == fn_address) {
            if (out_report) *out_report = g_slots[i].report;
            return true;
        }
    }
    return false;
}

} // namespace vpack::virtualizer
