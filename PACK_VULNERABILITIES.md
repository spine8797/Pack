# Báo cáo lỗ hổng packer — phân tích tĩnh `emu_release.exe`

> Phân tích 100% tĩnh qua IDA Pro (không xem source packer, không chạy file).
> Target: `emu_release.exe` (SHA-256 `51035ef525081a2b8a6571ca28a36a9b38bebd60eee8f4b40c36583e8a1086fb`)

## 1. Nhận diện

- Packer **custom**, không khớp packer thương mại nào (Hexacorn / PyPackerDetect / YARA section DB)
- Section layout: `.text .sbl1 .sbl2 .rdata .data .sbl5 .sbl6 .sbl7 .rsrc .reloc .4m4g7`
- Entry point: RVA `0xCCA00` (trong `.4m4g7`)
- Import gốc: đúng 3 hàm `LoadLibraryA`, `GetProcAddress`, `VirtualProtect`
- Header cấu hình tại `0x1400CC000` (`.4m4g7+0`): magic tĩnh `0xB5228A79`, runtime ghi magic `'VPCK'` (`0x4B435056`)
- OEP thật: **RVA `0x56E00`** (VA `0x140056E00`) — `mainCRTStartup` MSVC chuẩn

## 2. Cơ chế unpack (đã reverse đầy đủ)

```
Entry 0x1400CCA00
  ├─ push rax; xor eax,eax; jz $+2     (anti-disasm: nhảy đè lên call rác)
  ├─ pop rax; call sub_1400CCA80       (stub chính)
  ├─ OEP = [hdr+0xC] ^ [hdr+0x10]     (2 field đã được stage-2 patch)
  └─ jmp ImageBase(PEB) + OEP

sub_1400CCA80 (stub chính)
  ├─ VirtualProtect(base+0x1000, 0xCD000, RWX)   ← mở toàn bộ image, KHÔNG restore
  ├─ decrypt blob stage-2 (0x6A7 bytes @ hdr+0xB40)
  │    keystream: al = (NtGlobalFlag & 0x70) ^ 0x6D
  │    evolve:    rol al,5; add al,0x7F; xor al,0xFD
  ├─ call stage-2
  └─ rep stosb xóa blob

stage-2 (decrypt tĩnh được, 0x287 bytes code + 0x2D0 bảng descriptor)
  ├─ word [hdr+6] = 0                  (xóa re-entry flag, giá trị 0x2C = số chunk)
  ├─ r9  = (PEB->BeingDebugged << 13) ^ ((KUSER_SHARED_DATA+0x2D4 & 1) << 17)
  ├─ r11 = 0x6C9FF8E562DADFAF ^ r9
  ├─ xor qword [hdr+0x10], r11         (patch field OEP/key)
  ├─ new_key[hdr+0xC] = key ^ 0xFE3F123D ^ patched[hdr+0x10]
  ├─ 44 chunks × 0x18 (bảng descriptor):
  │    rva  = e[+0]  ^ 0xFE3F123D
  │    size = e[+4]  ^ 0x2ECB4B26
  │    key  = e[+8]  ^ 0x2ECB4B26FE3F123D ^ r9
  │    keystream: r10 = ror64(r10,13) + 0x9E3779B97F4A7C15 ; xor byte, r10b
  ├─ re-seal .sbl1 (RVA 0x7D000, 0x1CC27):
  │    key2 = patched[hdr+0x10](8 byte) ^ 0xCF50C8E3291058AE ^ r9
  │    → .sbl1 sau unpack = plain ^ keystream(key2)  (giải mã lazy bởi payload)
  ├─ relocation loop (count = 0)
  ├─ resolve IAT: LoadLibraryA/GetProcAddress theo descriptor @ RVA 0xB5F0C
  │    (ADVAPI32, USER32, SHELL32, CRYPT32, bcrypt, ncrypt, WINHTTP, KERNEL32)
  ├─ wipe: hdr+0x30..0x8EB (0x8BC), bảng descriptor, chuỗi DLL/hàm sau khi dùng
  └─ return → jmp OEP
```

Payload tự giữ module decrypt lazy trong `.sbl2` (cùng PRNG ror13+golden) để
giải mã `.sbl1` theo nhu cầu — `.text` có `call` trực tiếp vào `.sbl1`
(vd `0x140053347 → 0x14007D900`).

## 3. Lỗ hổng

### L1 — Unpack tĩnh 100% (nghiêm trọng nhất)
Mọi keystream là hàm tất định của hằng số tĩnh + 3 cờ debug đọc được từ
usermode. Không có entropy runtime, không mutation giữa các build. Đã chứng
minh thực tế: giải mã tĩnh `.text`, `.sbl1` (1 lớp), `.sbl2`, `.rdata`,
import table đầy đủ, OEP — **không cần thực thi file**. Viết auto-unpacker
generic 1 lần là chạy cho mọi sample cùng format.

### L2 — Anti-debug chỉ gồm 3 flag usermode
`NtGlobalFlag` (PEB+0xBC, mask 0x70), `BeingDebugged` (PEB+0x2),
`KdDebuggerEnabled` (0x7FFE02D4, bit 0). Cả 3 bị ScyllaHide/TitanHide che hoặc
patch thẳng trong process trước khi stub chạy. Thiếu hoàn toàn: RDTSC/timing,
`NtQueryInformationProcess(ProcessDebugPort)`, check DR register, int 2D,
hardware breakpoint, thread hiding, parent-process check.

### L3 — BUG: lớp anti-debug trên phép tính OEP tự triệt tiêu
Stage-2 patch cùng giá trị vào cả key (`+0xC`) lẫn OEP field (`+0x10`), rồi
stub ngoài tính `OEP = new_key ^ patched` — hai giá trị patched **cancell nhau**:
`OEP = key_static ^ 0xFE3F123D = 0x56E00` bất kể có debugger. Đoạn anti-debug
này là dead code về mặt toán học.

### L4 — Image giữ nguyên RWX sau unpack
`VirtualProtect(0xCD000, PAGE_EXECUTE_READWRITE)` không bao giờ restore
permissions → runtime patching/injection dễ dàng; đồng thời là heuristic phát
hiện packer rất mạnh.

### L5 — IAT resolve bằng tên plaintext
`LoadLibraryA/GetProcAddress` với tên DLL/hàm rõ ràng → hook/monitor được,
không API hashing, không import redirection. Dump tại OEP + Scylla fix IAT là
có binary chạy được.

### L6 — Không nén, giữ nguyên kích thước chunk
Layout gốc lộ hoàn toàn (chunk #00 = `.text` gốc tại RVA 0x1000 đúng vị trí,
các chunk nhỏ = từng structure import/reloc/CRT-init gốc); ranh giới section
vẫn thấy bằng entropy analysis.

### L7 — Chữ ký tĩnh cố định giữa các build
Magic `0xB5228A79` / `'VPCK'`; hằng `0xFE3F123D`, `0x2ECB4B26`,
`0x2ECB4B26FE3F123D`, `0xCF50C8E3291058AE`, `0x6C9FF8E562DADFAF`,
`0x9E3779B97F4A7C15`; tên section `.sbl*`/`.4m4g7`; bộ 3 imports; pattern junk
`xor eax,eax; jz $+2` — viết YARA được ngay, không cần mutation.

### L8 — Không anti-dump
Không SizeOfImage trick, không stolen bytes tại OEP, không xóa stub. Flag
re-entry tại `hdr+6` (word 0x2C) còn giúp file dump-rebuild chạy thẳng vào OEP.

### L9 — Relocation count = 0 + PE không DYNAMICBASE, không NXCOMPAT
Nếu bị load ở base khác (base bị chiếm / force ASLR) các tham chiếu tuyệt đối
(vtable trong `.data`) sẽ hỏng; NXCOMPAT tắt ⇒ DEP off cho payload.

### L10 — Metadata leak
`.data` (0xB8000–0xC3000), `.sbl7`, `.rsrc` không được mã hóa.

### L11 — Bảng descriptor bị lưu TRƯNG 2 bản trong file
Bản mã hóa trong blob stage-2 (bản runtime dùng) **và** bản plaintext-obfuscated
(only XOR hằng) tại `header+0x30` (0x2C × 0x18 bytes). Bản ở header không hề
được runtime đọc (chỉ bị wipe) — tức người phân tích có toàn bộ bảng
RVA/size/key chunk mà **không cần giải mã stage-2**.

### L12 — Re-seal `.sbl1` (lazy decrypt) cũng bẻ tĩnh được
Key re-seal = `patched[hdr+0x10] ^ 0xCF50C8E3291058AE ^ r9` — thuần hàm của
hằng số tĩnh (r9=0 khi sạch). File lưu `.sbl1 = plain ^ s_layer_bảng` nên
decrypt 1 lớp bằng key trong bảng descriptor là ra plaintext đầy đủ (đã
chứng minh: 45 functions hợp lệ). Cơ chế "lazy" chỉ cản dump runtime, không
cản phân tích tĩnh.

## 4. Kết quả unpack tĩnh (chứng minh)

| Vùng | Kết quả |
|---|---|
| `.text` (0x7B75C) | 1029 functions, Hex-Rays decompile OK |
| `.sbl1` (0x1CC27) | 45 functions (call target `0x14007D900` = prologue chuẩn) |
| `.sbl2` (0x1522) | module decrypt lazy của payload (PRNG ror13+golden) |
| `.rdata` + các chunk nhỏ | strings 627 → 1552, CRT-init table, import structures |
| Import | 8 DLL: ADVAPI32, USER32, SHELL32, CRYPT32, bcrypt, ncrypt, WINHTTP, KERNEL32 |
| OEP | `0x140056E00` (`sub rsp,28h; call __security_init_cookie; add rsp,28h; jmp __scrt_common_main_seh`) |
| **Tổng** | **1094 functions** phục hồi toàn bộ, decompile pseudocode được |

Hằng số phục dựng (r9 = 0, chạy sạch):

```
stage2_key  : al0 = 0x6D; rol5; +0x7F; ^0xFD (per byte, xor trước evolve sau)
chunk_rva   : e[+0]  ^ 0xFE3F123D
chunk_size  : e[+4]  ^ 0x2ECB4B26
chunk_key   : e[+8]  ^ 0x2ECB4B26FE3F123D
keystream   : r10 = ror64(r10,13) + 0x9E3779B97F4A7C15; xor byte với r10b
reseal_key2 : 0x1D77A8E56344FA7F ^ 0xCF50C8E3291058AE
OEP_rva     : 0xFE3A7C3D ^ 0xFE3F123D = 0x56E00
```

## 5. Khuyến nghị khắc phục (theo mức ưu tiên)

1. Trộn entropy runtime vào key chunk (vd: đọc timer/hardware RNG khi pack và
   lưu seed đã obfuscate) — phá auto-unpacker generic.
2. Bỏ/V Payload-side: thay 3 cờ debug bằng các check khó che hơn (timing,
   DR registers, NtQueryInformationProcess, self-CRC).
3. Sửa bug L3 (OEP cancel) hoặc bỏ hẳn — đang tốn công mà không chống được gì.
4. Restore section permissions sau unpack (RWX → RX/R theo bảng gốc).
5. API hashing / import redirection thay vì LoadLibraryA+GetProcAddress plaintext.
6. Thêm nén (LZMA/aPLib) trước mã hóa — phá ánh xạ 1-1 chunk↔section.
7. Randomize section name + hằng số mỗi build (mutation).
8. Đặt DYNAMICBASE/NXCOMPAT; xử lý relocation thật thay vì count=0.
9. Bỏ bản bảng descriptor thứ hai ở `header+0x30` (không dùng mà lộ key).
