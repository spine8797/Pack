# VPack v0.3 — Integration Guide & Operational Notes

This document explains how to integrate the **VPack** protection SDK and PE64 packer (`vpack_cli`) into a Windows x64 C++17/20 project (CMake or Visual Studio / MSBuild), how to use each protection primitive, and the exact architectural rules to keep in mind for rock-solid runtime stability.

---

## 1. Architecture Overview

VPack combines **pack-time PE64 transformation** (`vpack_cli`) with **in-process runtime hardening** (`vpack` static library):

| Protection Layer | Section / Component | Behavior on Disk & in Memory |
| :--- | :--- | :--- |
| **2-Stage W^X PE64 Packer** | Randomized stub section (e.g. `.xz0lu`) | Encrypts `.text`, `.vcode`, `.vinit`, `.vpvlt`, `.pdata`, `.xdata`, `.idata`, and `.rdata` string/constant intervals. Zero `RWX` sections on disk; `master_seed` on disk stores only a `public_salt`. |
| **Self-Wiping Init** | `.vinit` (`VPACK_INIT_CODE`) | Restores strict `RX` / `RW` / `R` permissions, registers `.pdata` unwind tables, restores TLS callbacks, wipes 100% of the unpacker stub, then wipes & locks `.vinit` to `PAGE_NOACCESS`. |
| **Lazy `.text` Page Vault** | `.vpvlt` (`vpack::vault`) | Encrypts `.text` into an XOR-masked `PAGE_NOACCESS` heap vault and zeroes/locks `.text` pages to `PAGE_NOACCESS`. Decrypts at most `VPACK_VAULT_WINDOW` (8) pages on demand via VEH + Indirect Syscall. |
| **JIT Execute & Re-Key Vault** | `.vcode` (`VPACK_CODE`) | Keeps sensitive functions encrypted and `PAGE_READONLY` at rest. Decrypts to `PAGE_EXECUTE_READ` only inside `VPACK_JIT_CALL(...)`, then immediately re-encrypts with a new rolling key on return. |
| **AOT x64-to-VM Shredder** | `VPACK_VIRTUALIZE_FN` | At pack time, lifts compiled x86_64 functions into Polymorphic Hybrid MBA VM bytecode and overwrites the native machine code **on disk** with `JMP thunk + UD2 + noise` (zero native instructions shipped). |
| **Compile-Time Hybrid VM** | `ConstexprVmBuilder` | Assembles and rolling-encrypts VM programs 100% at C++ compile time with MBA, `GF(2^64)`, dynamic register rotation, encrypted VM stack, and branchless environmental key entanglement. |
| **Indirect Syscall Engine** | `resolve_ntdll_syscall` | Recovers exact Kernel SSNs via an RVA-sorted `Zw*` export table + neighbor inspection and executes through clean `syscall; ret` gadgets inside `ntdll.dll` (defeats user-mode inline hooks like ScyllaHide). |
| **5-Layer Anti-VM** | `vpack::antivm` | Detects VMware, VirtualBox, QEMU, KVM, Xen, Parallels, and Hyper-V Guest VMs via CPUID, RSMB SMBIOS, guest-only kernel devices, and VMware port `0x5658`, while safely whitelisting Windows 10/11 VBS / Core Isolation / WSL2 physical hosts. |

> **Note on DLL Injection:** Module-list / unsigned-DLL injection blocking has been intentionally removed so delay-loaded Windows subsystems (`WinHTTP`, `Schannel`, `BCrypt`) and legitimate user overlays (Discord, Steam, NVIDIA, IMEs) never trigger false positives.

---

## 2. Build System Integration

### Option A: CMake Project (MinGW-w64 GCC or MSVC)

1. Link your target against the `vpack` static library and required Windows system libraries.
2. Add a `POST_BUILD` step invoking `vpack_cli pack` to produce the standalone packed executable.

```cmake
# Add VPack subdirectory (if not already in your root CMakeLists.txt)
add_subdirectory(path/to/Pack vpack_build)

add_executable(my_app
    src/main.cpp
)

# Link VPack SDK + Windows system libraries
target_link_libraries(my_app PRIVATE
    vpack
    Advapi32 User32 Psapi Kernel32 Ntdll
)

# Recommended compiler/linker flags for clean section layout & symbol stripping
if(MSVC)
    target_compile_options(my_app PRIVATE /EHsc /Gy /Gw /MT)
    target_link_options(my_app PRIVATE /OPT:REF /OPT:ICF)
else()
    target_compile_options(my_app PRIVATE -ffunction-sections -fdata-sections -fvisibility=hidden -g0)
    target_link_options(my_app PRIVATE -static -static-libgcc -static-libstdc++ -Wl,--gc-sections -Wl,--strip-all -s)
endif()

# Automatically pack the compiled binary after every build
add_custom_command(TARGET my_app POST_BUILD
    COMMAND $<TARGET_FILE:vpack_cli> pack $<TARGET_FILE:my_app> "${CMAKE_BINARY_DIR}/my_app_protected.exe"
    COMMENT "Packing my_app -> my_app_protected.exe"
)
```

### Option B: Visual Studio (`.vcxproj` / MSBuild)

1. **C/C++ -> General -> Additional Include Directories**: Add `F:\Project\Pack\include`.
2. **C/C++ -> Language -> C++ Language Standard**: Set to **ISO C++17 (`/std:c++17`)** or **ISO C++20 (`/std:c++20`)**.
3. **Add Source Files** (or link `vpack.lib`): Include the 9 `.cpp` files under `F:\Project\Pack\src\` (`crypto.cpp`, `anti_debug.cpp`, `anti_vm.cpp`, `anti_dump.cpp`, `page_vault.cpp`, `vm.cpp`, `virtualizer.cpp`, `pe_parser.cpp`, `vpack_sdk.cpp`).
4. **Linker -> Input -> Additional Dependencies**: Ensure `advapi32.lib;user32.lib;psapi.lib;kernel32.lib;ntdll.lib` are present.
5. **Linker -> Debugging -> Generate Debug Info**: Strip PDB path in Release builds (`/PDBALTPATH:%_PDB%` or disable debug info) if desired — note that `vpack_cli pack` automatically strips the Debug Directory and COFF symbols anyway.
6. **Build Events -> Post-Build Event -> Command Line**:
   ```bat
   "F:\Project\Pack\build\vpack_cli.exe" pack "$(TargetPath)" "$(OutDir)$(TargetName)_protected.exe"
   ```

---

## 3. Step-by-Step SDK Usage in Code

### Step 1: Initialize `vpack::Protector` at Process Startup

Always call `vpack::Protector::initialize(...)` as early as possible inside `main()` / `wWinMain()`.

```cpp
#include "vpack/vpack.h"

int main() {
    // Default maximum security (wipes MZ/PE headers to 0x0000)
    // NOTE: If your app uses WinHTTP (e.g., KeyAuth / REST APIs), include vpack::PROT_PE_SKELETON!
    const auto status = vpack::Protector::initialize(
        vpack::PROT_DEFAULT | vpack::PROT_PE_SKELETON
    );

    if (status.initial_debug_report.detected()) {
        // Optional: react to debugger / VM detection, or feed flags into key derivation
    }

    // ... application logic ...
    return 0;
}
```

### Step 2: String Encryption (Synthesize & Wipe)

Wrap sensitive string literals (URLs, pipe names, registry keys, prompts, error messages) with `VPACK_STR("...")`.
- Strings are encrypted at compile time using a `GF(2^64)` + non-linear MBA stream keyed per file/line/build-time.
- At runtime, `VPACK_STR` returns a `WipedString` temporary that **automatically overwrites its heap/SSO buffer with random noise + zeroes** at the end of the full expression.

```cpp
// GOOD: Decrypted on the fly, passed to Win32/CRT call, and immediately scrubbed!
std::printf("%s\n", VPACK_STR("Connecting to license gateway...").c_str());

// AVOID storing .c_str() in a raw pointer, because the temporary WipedString is wiped at ';'
// const char* bad = VPACK_STR("dangling pointer!").c_str(); // <-- DO NOT DO THIS!

// GOOD if you need the string across multiple lines within a scope:
{
    auto endpoint = VPACK_STR("https://api.example.com/v1/verify");
    send_request(endpoint.c_str());
} // <-- Scrubbed from RAM right here when `endpoint` leaves scope
```

### Step 3: Hidden API Imports (Zero IAT Footprint)

Use `VPACK_IMPORT` for sensitive Win32 / Native APIs so their names never appear in `.idata` or strings:

```cpp
using FnIsWow64Process = BOOL(WINAPI*)(HANDLE, PBOOL);
static auto fn_wow64 = VPACK_IMPORT(FnIsWow64Process, "kernel32.dll", "IsWow64Process");

BOOL is_wow64 = FALSE;
if (fn_wow64.get()) {
    fn_wow64(GetCurrentProcess(), &is_wow64);
}
```

### Step 4: JIT Execute & Re-Key Functions (`.vcode`)

Place critical functions in `.vcode` using `VPACK_CODE` and **always** invoke them via `VPACK_JIT_CALL`:

```cpp
VPACK_CODE bool verify_session_token(uint64_t token, uint64_t hwid_hash) {
    // This machine code is PAGE_READONLY & encrypted in RAM whenever idle!
    uint64_t sig = vpack::crypto::mba_xor(token, hwid_hash);
    return sig == 0x6087D00B38033655ULL;
}

void authenticate_user(uint64_t token, uint64_t hwid) {
    // Unlocks .vcode -> verifies MAC -> decrypts to RX -> executes -> rotates key & re-locks to R
    bool valid = VPACK_JIT_CALL(verify_session_token, token, hwid);
}
```

### Step 5: AOT x86_64-to-VM Function Virtualization & On-Disk Shredding

To lift a compiled C++ function into the Polymorphic Hybrid VM and shred its x86_64 instructions on disk:

```cpp
VPACK_CODE uint64_t derive_unlock_key(uint64_t seed, uint64_t user_hash) {
    uint64_t state = seed ^ 0xA381E5C9D72B4F19ULL;
    for (int i = 0; i < 16; ++i) {
        uint64_t rot = (state << 11) | (state >> 53);
        state = (rot + (user_hash ^ static_cast<uint64_t>(i * 0x9E3779B9u))) ^ 0xBF58476D1CE4E5B9ULL;
    }
    return state;
}

int main() {
    vpack::Protector::initialize(vpack::PROT_DEFAULT);

    // Activates the AOT-shredded VM slot (or lifts & shreds in RAM during unpacked dev builds)
    const auto lift_info = VPACK_VIRTUALIZE_FN(&derive_unlock_key);

    // If the function carries VPACK_CODE, keep calling it via VPACK_JIT_CALL
    // (because VM handlers also reside in .vcode):
    uint64_t key = VPACK_JIT_CALL(derive_unlock_key, 0x1234ULL, 0x5678ULL);
}
```

### Step 6: Background Anti-Debug / Anti-VM Watchdog & Silent Key Poisoning

Instead of an easily patchable `if (is_debugged) exit(1);`, entangle `compute_environmental_key_poison()` directly into your decryption keys or start the hidden watchdog thread:

```cpp
// 1. Background hidden thread (spawned via Indirect Syscall with HIDE_FROM_DEBUGGER = 0x04)
//    Automatically rotates the idle .vcode encryption key on every tick!
vpack::antidebug::Watchdog watchdog;
watchdog.start(200, [](const vpack::antidebug::DebugReport& rep) {
    // Triggered on debugger attach, hardware breakpoints, ntdll hooks, code tamper, or Guest VM
});

// 2. Branchless key entanglement (returns 0ULL on clean physical host, non-zero poison if hostile)
uint64_t live_key = base_secret_key ^ vpack::antidebug::compute_environmental_key_poison();
```

---

## 4. CLI Usage (`vpack_cli`)

```powershell
# Pack a 64-bit PE executable (default: full anti-debug stub + AOT VM shredding + symbol stripping)
vpack_cli.exe pack input_app.exe output_app_packed.exe

# Pack with a deterministic 64-bit seed (useful for reproducible builds)
vpack_cli.exe pack input_app.exe output_app_packed.exe --seed 0x1337C0DEBEEF2026

# Pack without stub-level PEB/KdDebugger key perturbation (useful when debugging startup crashes)
vpack_cli.exe pack input_app.exe output_app_packed.exe --no-anti-debug

# Inspect section permissions, public salt, encrypted region count, and original OEP
vpack_cli.exe inspect output_app_packed.exe
```

---

## 5. Critical Operational Notes & Gotchas (Read Before Shipping!)

### 1. `WinHTTP` / Lazy Header Consumers -> Enable `PROT_PE_SKELETON`
By default, `PROT_ANTI_DUMP` wipes the entire 4KB PE header page at `ImageBase` to `0x00` (`MZ = 0x0000`).
However, certain Windows DLLs — most notably **`winhttp.dll` (`WinHttpOpen`)**, version-resource APIs, and callers of `RtlImageNtHeader(GetModuleHandle(NULL))` — lazily re-parse the main executable's DOS/NT header at runtime and can hang or fail if `MZ` is zeroed.
- **Rule:** If your application uses `WinHTTP` (such as KeyAuth), COM activation, or embedded Win32 resources, initialize with:
  ```cpp
  vpack::Protector::initialize(vpack::PROT_DEFAULT | vpack::PROT_PE_SKELETON);
  ```
  `PROT_PE_SKELETON` wipes 100% of section headers, imports, exports, relocations, debug directories, and `AddressOfEntryPoint`, leaving only an empty zero-section shell so Windows APIs work seamlessly while dumpers still get an unrebuildable dead shell.

### 2. Never Pass Raw `.text` Function Pointers as Read Buffers to Kernel Syscalls
When `PROT_PAGE_VAULT` is active, ~96% of `.text` pages are locked to `PAGE_NOACCESS` at any given moment. User-mode instruction fetches trigger the VEH in `.vpvlt` and transparently decrypt the page, **but the Windows Kernel (`WriteFile`, `send`, etc.) does not fire user-mode VEH** when reading a buffer pointer — it simply returns `ERROR_NOACCESS` (`998`).
- String literals and `constexpr` arrays live in `.rdata` (not `.text`), so normal Win32/CRT calls work without issue.
- Only avoid passing raw addresses of functions inside `.text` directly into kernel I/O syscalls.

### 3. `VPACK_CODE` Calling Rules (Avoid DEP Faults & Deadlocks)
Functions marked `VPACK_CODE` live in `.vcode`, which is locked to `PAGE_READONLY` (non-executable) when idle.
1. **Always call `VPACK_CODE` functions through `VPACK_JIT_CALL(fn, ...)`** (recursive/nested calls inside an active `VPACK_JIT_CALL` are supported on the same thread).
2. **Never pass a `VPACK_CODE` function directly as an OS callback** (`CreateThread` start routine, `WndProc`, timer callback, or VEH handler) — wrap it in a normal `.text` trampoline that invokes `VPACK_JIT_CALL` inside.
3. **Keep `VPACK_CODE` functions short and CPU-bound** (crypto, key derivation, signature checks, packet encoding). Do **not** block on `fgets`, `Sleep`, network I/O, or cross-thread mutexes inside `VPACK_JIT_CALL`, because `.vcode` remains decrypted (`RX`) and holds the JIT spinlock until the outermost `VPACK_JIT_CALL` on that thread returns.

### 4. `VPACK_VIRTUALIZE_FN` Supported Subset & Limits
The x86_64-to-VM Lifter (`src/virtualizer.cpp`) is purpose-built for **integer/pointer cryptographic and licensing routines**, not arbitrary UI/STL megafunctions:
- **Slot & Size Limits:** Up to **16** virtualized functions per binary (`kMaxVirtualizedSlots = 16`), scanning up to `2048` native bytes and producing up to `2048` bytes of encrypted VM bytecode per slot (~300–350 x64 instructions).
- **ABI & Instructions:** Supports Windows x64 integer/pointer ABI (`RCX, RDX, R8, R9` -> `RAX`), local stack variables, 8/16/32/64-bit loads/stores (including `AH/CH/DH/BH`), `LEA`, `MOVZX`/`MOVSX`/`MOVSXD`, `CMOVcc`, `SETcc`, all `Jcc` branches, shifts/rotates, `IMUL`, and direct/indirect `CALL` up to 6 integer arguments.
- **Unsupported Instructions:** Floating-point / SIMD (`SSE`, `AVX`, `XMM` registers), `DIV`/`IDIV`, `switch` jump-tables (`jmp rax`), and C++ `throw`/`try`/`catch` inside the virtualized function itself. (If an unsupported instruction is encountered at pack time, `vpack_cli` safely skips AOT lifting rather than corrupting the binary.)
- **Tip:** Mark functions intended for `VPACK_VIRTUALIZE_FN` with `VPACK_NOINLINE` (or `VPACK_CODE`) so the compiler does not inline them into `main()` before `vpack_cli` can shred them on disk.

### 5. Packing Third-Party Executables Without the SDK
`vpack_cli` is designed to pair with binaries linked against the `vpack` static library (`vpack::Protector::initialize()`).
If you run `vpack_cli pack` on an external `.exe` that **does not** call `Protector::initialize()`:
- Stage 1 & Stage 2 will still unpacksections, resolve imports, wipe import names, and run the program, **but** `.pdata` exception tables will not be re-registered with `RtlAddFunctionTable`, and the memory pages unlocked by Stage 1 will remain `RWX` instead of locking down into `PageVault` / `JIT Vault`.

### 6. Windows 10/11 VBS / Core Isolation vs. Real Virtual Machines
Modern Windows 11 gaming and developer PCs almost always run under the Hyper-V hypervisor due to **Core Isolation / Memory Integrity (VBS)** or **WSL2**.
- `vpack::antivm` explicitly checks Hyper-V TLFS leaf `0x40000003` (`CreatePartitions` privilege bit in `EBX`) so **physical Windows hosts with VBS/WSL2 enabled report `VmVendor::HostVbsOrRoot` and `is_virtual_machine() == false` (0 false positives)**, while actual Hyper-V Guest VMs, VMware, VirtualBox, QEMU, and KVM are accurately flagged and poison the VM key schedule.

### 7. Threat-Model Boundary
VPack operates entirely in **User Mode (Ring 3)** and represents near-maximum hardening achievable without a kernel driver. Against a kernel-mode hypervisor debugger (e.g., HyperDbg using EPT hooks or TitanHide in Ring 0), pair VPack's client-side obfuscation with **server-side validation** so critical secrets or game/app payloads are never statically shipped before authentication succeeds.
