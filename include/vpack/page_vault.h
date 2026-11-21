#pragma once
// ============================================================================
// page_vault.h — Lazy per-page code decryption (NO THREAD, window-based)
//
// Van de (do duoc tren build truoc):
//   Stub decrypt TOAN BO .text mot lan roi giu RX -> tool tu ngoai poll
//   VirtualQueryEx + ReadProcessMemory lay du 214/214 trang plaintext.
//   "Zero-RWX" chi doi quyen SAU decrypt, khong re-encrypt -> vo dung.
//
// Giai phap: .text luon MA HOA + NOACCESS. CPU fetch vao trang nao -> VEH
// decrypt DUNG trang do tu cipher master (heap NOACCESS). Chi giu toi da
// VPACK_VAULT_WINDOW trang plaintext (FIFO); trang cu nhat bi ZERO +
// NOACCESS lai ngay khi cua so day — HOAN TOAN TRONG VEH, KHONG CAN THREAD.
//
//   * Khong thread/watchdog: khong bi suspend lam mat retire; khong them CPU.
//   * Retire "mu" an toan: thread khac dang chay trong trang bi zero thi
//     instruction ke tiep fault -> decrypt lai (khong crash).
//
// Rang buoc:
//   - Chi decrypt khi fault la INSTRUCTION-FETCH tai chinh trang do
//     (RIP & ~0xFFF == page) -> tu choi memcpy/RPM noi bo cua scanner.
//   - Packer phai ma hoa tung trang bang:
//       seed_page = splitmix64(master_seed ^ page_index*0x1000)
//       cipher[i] = plain[i] ^ splitmix_stream(seed_page)[i]
// ============================================================================

#ifndef VPACK_PAGE_VAULT_H
#define VPACK_PAGE_VAULT_H

#include "vpack/config.h"
#include <cstdint>
#include <cstddef>

namespace vpack::vault {

// Bat lazy vault cho vung code [code_base, code_base+code_size).
// - Neu cipher == nullptr: tu dong ma hoa in-place tu code_base (da relocate ASLR) vao heap cipher master.
// - copy/encrypt cipher -> heap NOACCESS (con tro duoc XOR-mask trong RAM)
// - dat toan vung NOACCESS + cai VEH (toan bo handler nam trong section .vpvlt rieng biet)
// - code_base phai page-aligned
VPACK_VAULT_CODE bool install(void* code_base, size_t code_size,
             const uint8_t* cipher, uint64_t master_seed) noexcept;

// Dong bo lai cipher master neu mot doan code trong .text duoc patch hop le (vd: runtime virtualizer)
VPACK_VAULT_CODE void sync_modified_range(const void* address, size_t size) noexcept;

// Tat vault (restore trang thai - dung cho test/unload)
VPACK_VAULT_CODE void uninstall() noexcept;

// true khi vault dang hoat dong
VPACK_VAULT_CODE bool active() noexcept;

// FNV-1a cua CIPHER MASTER (khong doi khi decrypt/retire)
// -> dung thay cho live .text hash trong integrity check
VPACK_VAULT_CODE uint64_t cipher_hash() noexcept;

} // namespace vpack::vault

#endif // VPACK_PAGE_VAULT_H
