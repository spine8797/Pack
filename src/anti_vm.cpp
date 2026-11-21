#include "vpack/anti_vm.h"
#include "vpack/anti_dump.h"
#include "vpack/crypto.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <intrin.h>
#include <cstring>

namespace vpack::antivm {

namespace {

VPACK_FORCEINLINE void cpuid_leaf(int regs[4], uint32_t leaf) noexcept {
#if defined(_MSC_VER)
    __cpuid(regs, static_cast<int>(leaf));
#elif defined(__GNUC__) || defined(__clang__)
    uint32_t a = 0, b = 0, c = 0, d = 0;
    __asm__ volatile(
        "cpuid"
        : "=a"(a), "=b"(b), "=c"(c), "=d"(d)
        : "a"(leaf), "c"(0)
    );
    regs[0] = static_cast<int>(a);
    regs[1] = static_cast<int>(b);
    regs[2] = static_cast<int>(c);
    regs[3] = static_cast<int>(d);
#else
    regs[0] = regs[1] = regs[2] = regs[3] = 0;
#endif
}

bool contains_ascii_ci(const uint8_t* hay, size_t hay_len, const char* needle) noexcept {
    if (!hay || !needle || hay_len == 0) return false;
    size_t nlen = 0;
    while (needle[nlen] != '\0') ++nlen;
    if (nlen == 0 || nlen > hay_len) return false;

    for (size_t i = 0; i + nlen <= hay_len; ++i) {
        bool match = true;
        for (size_t j = 0; j < nlen; ++j) {
            uint8_t hc = hay[i + j];
            uint8_t nc = static_cast<uint8_t>(needle[j]);
            if (hc >= 'A' && hc <= 'Z') hc = static_cast<uint8_t>(hc + ('a' - 'A'));
            if (nc >= 'A' && nc <= 'Z') nc = static_cast<uint8_t>(nc + ('a' - 'A'));
            if (hc != nc) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

VmVendor classify_cpuid_vendor_12(const char vendor[13], bool& out_is_microsoft_hv) noexcept {
    out_is_microsoft_hv = false;
    const auto* v = reinterpret_cast<const uint8_t*>(vendor);
    if (contains_ascii_ci(v, 12, "VMwareVMware")) return VmVendor::VMware;
    if (contains_ascii_ci(v, 12, "VBoxVBoxVBox")) return VmVendor::VirtualBox;
    if (contains_ascii_ci(v, 12, "KVMKVMKVM"))    return VmVendor::KVM;
    if (contains_ascii_ci(v, 12, "TCGTCGTCGTCG")) return VmVendor::QEMU;
    if (contains_ascii_ci(v, 12, "XenVMMXenVMM")) return VmVendor::Xen;
    if (contains_ascii_ci(v, 12, "prpe hyperv") ||
        contains_ascii_ci(v, 12, "lrpepyh vr"))   return VmVendor::Parallels;
    if (contains_ascii_ci(v, 12, "bhyve bhyve"))  return VmVendor::Bhyve;
    if (contains_ascii_ci(v, 12, "Microsoft Hv")) {
        out_is_microsoft_hv = true;
    }
    return VmVendor::None;
}

void check_cpuid_hypervisor(VmReport& rep) noexcept {
    int regs[4]{};
    cpuid_leaf(regs, 1u);
    rep.hypervisor_bit = (static_cast<uint32_t>(regs[2]) & (1u << 31)) != 0;
    if (!rep.hypervisor_bit) {
        return;
    }

    // Check primary hypervisor leaf 0x40000000 and nested leaf 0x40000100
    bool is_ms_hv = false;
    for (uint32_t base_leaf : {0x40000000u, 0x40000100u}) {
        int hv_regs[4]{};
        cpuid_leaf(hv_regs, base_leaf);
        char vendor_str[13]{};
        std::memcpy(vendor_str + 0, &hv_regs[1], 4); // EBX
        std::memcpy(vendor_str + 4, &hv_regs[2], 4); // ECX
        std::memcpy(vendor_str + 8, &hv_regs[3], 4); // EDX

        bool leaf_ms_hv = false;
        VmVendor v = classify_cpuid_vendor_12(vendor_str, leaf_ms_hv);
        if (leaf_ms_hv) {
            is_ms_hv = true;
        }
        if (v != VmVendor::None) {
            rep.vendor = v;
            rep.flags |= VM_CPUID_HYPERVISOR_VENDOR;
            return;
        }
    }

    if (is_ms_hv) {
        // Distinguish physical Windows 10/11 Host (VBS / Core Isolation / WSL2 Root Partition)
        // from an actual Guest VM using Hyper-V TLFS leaf 0x40000003 partition privilege flags:
        // Bit 0 of EBX (CreatePartitions) is ONLY granted to the Host Root Partition!
        int priv_regs[4]{};
        cpuid_leaf(priv_regs, 0x40000003u);
        const uint32_t ebx_priv = static_cast<uint32_t>(priv_regs[1]);
        if ((ebx_priv & 0x01u) != 0) {
            rep.vendor = VmVendor::HostVbsOrRoot;
        } else {
            rep.vendor = VmVendor::HyperVGuest;
            rep.flags |= VM_HYPERV_GUEST_PARTITION;
        }
    }
}

void check_smbios_firmware(VmReport& rep) noexcept {
    using FnGetSystemFirmwareTable = UINT(WINAPI*)(DWORD, DWORD, PVOID, DWORD);
    static auto fn_get_fw = VPACK_IMPORT(
        FnGetSystemFirmwareTable, "kernel32.dll", "GetSystemFirmwareTable"
    );
    if (!fn_get_fw.get()) return;

    constexpr DWORD kRsmbSig = 0x52534D42u; // 'RSMB'
    UINT needed = fn_get_fw(kRsmbSig, 0, nullptr, 0);
    if (needed == 0 || needed > 65536u) return;

    uint8_t buf[8192]{};
    uint8_t* table_buf = buf;
    bool heap_alloc = false;
    if (needed > sizeof(buf)) {
        table_buf = static_cast<uint8_t*>(
            VirtualAlloc(nullptr, needed, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        );
        if (!table_buf) return;
        heap_alloc = true;
    }

    UINT written = fn_get_fw(kRsmbSig, 0, table_buf, needed);
    if (written > 8 && written <= needed) {
        VmVendor detected = VmVendor::None;
        if (contains_ascii_ci(table_buf, written, "vmware")) {
            detected = VmVendor::VMware;
        } else if (contains_ascii_ci(table_buf, written, "virtualbox") ||
                   contains_ascii_ci(table_buf, written, "innotek")) {
            detected = VmVendor::VirtualBox;
        } else if (contains_ascii_ci(table_buf, written, "qemu") ||
                   contains_ascii_ci(table_buf, written, "bochs")) {
            detected = VmVendor::QEMU;
        } else if (contains_ascii_ci(table_buf, written, "kvm")) {
            detected = VmVendor::KVM;
        } else if (contains_ascii_ci(table_buf, written, "parallels")) {
            detected = VmVendor::Parallels;
        } else if (contains_ascii_ci(table_buf, written, "bhyve")) {
            detected = VmVendor::Bhyve;
        } else if (contains_ascii_ci(table_buf, written, "microsoft corporation") &&
                   contains_ascii_ci(table_buf, written, "virtual machine")) {
            detected = VmVendor::HyperVGuest;
            rep.flags |= VM_HYPERV_GUEST_PARTITION;
        }

        if (detected != VmVendor::None) {
            rep.vendor = detected;
            rep.flags |= VM_SMBIOS_FIRMWARE;
        }
    }

    crypto::secure_wipe(table_buf, written, 0x9E3779B97F4A7C15ULL);
    if (heap_alloc) {
        VirtualFree(table_buf, 0, MEM_RELEASE);
    }
}

bool probe_guest_device(const char* device_path) noexcept {
    using FnCreateFileA  = HANDLE(WINAPI*)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
    using FnCloseHandle  = BOOL(WINAPI*)(HANDLE);
    static auto fn_create = VPACK_IMPORT(FnCreateFileA, "kernel32.dll", "CreateFileA");
    static auto fn_close  = VPACK_IMPORT(FnCloseHandle, "kernel32.dll", "CloseHandle");
    if (!fn_create.get()) return false;

    HANDLE h = fn_create(
        device_path,
        0, // Query existence only (does not require admin rights)
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr
    );
    if (h != INVALID_HANDLE_VALUE) {
        if (fn_close.get()) fn_close(h);
        return true;
    }
    return false;
}

void check_guest_devices(VmReport& rep) noexcept {
    // Only check GUEST-exclusive kernel device objects (never host-side drivers like vmci/VBoxDrv)
    if (probe_guest_device("\\\\.\\vmmemctl") || probe_guest_device("\\\\.\\hgfs")) {
        rep.vendor = VmVendor::VMware;
        rep.flags |= VM_GUEST_DEVICE_DRIVER;
        return;
    }
    if (probe_guest_device("\\\\.\\VBoxGuest") || probe_guest_device("\\\\.\\VBoxMiniRdrDN")) {
        rep.vendor = VmVendor::VirtualBox;
        rep.flags |= VM_GUEST_DEVICE_DRIVER;
        return;
    }
    if (probe_guest_device("\\\\.\\vioser") || probe_guest_device("\\\\.\\Balloon")) {
        if (rep.vendor == VmVendor::None || rep.vendor == VmVendor::HostVbsOrRoot) {
            rep.vendor = VmVendor::QEMU;
        }
        rep.flags |= VM_GUEST_DEVICE_DRIVER;
    }
}

// Placed in .vpvlt so it is NEVER inside an evicted .text page when PageVault is active!
VPACK_VAULT_CODE LONG CALLBACK vmware_port_veh(PEXCEPTION_POINTERS ex) noexcept {
    if (ex->ExceptionRecord->ExceptionCode == EXCEPTION_PRIV_INSTRUCTION) {
        const auto* ip = reinterpret_cast<const uint8_t*>(ex->ContextRecord->Rip);
        // 0xED is `in eax, dx`: skip the 1-byte privileged instruction and clear RBX
        if (ip && ip[0] == 0xED) {
            ex->ContextRecord->Rbx = 0;
            ex->ContextRecord->Rip += 1;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

#if defined(_MSC_VER) && defined(_M_X64)
#pragma section(".vpvlt", execute, read)
#pragma code_seg(".vpvlt")
__declspec(allocate(".vpvlt")) alignas(16) const uint8_t kMsvcVmwarePortStub[24] = {
    0x53,                               // push rbx
    0xB8, 0x68, 0x58, 0x4D, 0x56,       // mov eax, 0x564D5868 ('VMXh')
    0x31, 0xDB,                         // xor ebx, ebx
    0xB9, 0x0A, 0x00, 0x00, 0x00,       // mov ecx, 10 (CMD_GETVERSION)
    0xBA, 0x58, 0x56, 0x00, 0x00,       // mov edx, 0x5658 ('VX')
    0xED,                               // in eax, dx (faults on non-VMware -> vmware_port_veh skips & zeroes rbx)
    0x89, 0xD8,                         // mov eax, ebx
    0x5B,                               // pop rbx
    0xC3, 0x90                          // ret; nop
};
#pragma code_seg()
#endif

void check_vmware_io_port(VmReport& rep) noexcept {
#if defined(_M_X64) || defined(__x86_64__)
    // Register with First=0 so PageVault's vault::veh (First=1 in .vpvlt) always runs first
    PVOID h_veh = AddVectoredExceptionHandler(0, vmware_port_veh);
    if (!h_veh) return;

    uint32_t ebx_val = 0u;
#if defined(__GNUC__) || defined(__clang__)
    uint32_t eax_val = 0x564D5868u; // 'VMXh'
    uint32_t ecx_val = 10u;         // CMD_GETVERSION
    uint32_t edx_val = 0x5658u;     // 'VX'

    __asm__ volatile(
        "in %%dx, %%eax"
        : "+a"(eax_val), "+b"(ebx_val), "+c"(ecx_val), "+d"(edx_val)
        :
        : "cc"
    );
#elif defined(_MSC_VER)
    using FnVmwarePortProbe = uint32_t(*)() noexcept;
    const auto fn_probe = reinterpret_cast<FnVmwarePortProbe>(
        reinterpret_cast<const void*>(&kMsvcVmwarePortStub[0])
    );
    ebx_val = fn_probe();
#endif

    RemoveVectoredExceptionHandler(h_veh);

    if (ebx_val == 0x564D5868u) {
        rep.vendor = VmVendor::VMware;
        rep.flags |= VM_VMWARE_IO_PORT;
    }
#else
    (void)rep;
#endif
}

void check_cpuid_timing(VmReport& rep) noexcept {
    int regs[4]{};
    uint64_t min_delta = ~0ULL;

    for (int i = 0; i < 16; ++i) {
        const uint64_t t1 = __rdtsc();
        cpuid_leaf(regs, 1u);
        const uint64_t t2 = __rdtsc();
        if (t2 > t1) {
            const uint64_t d = t2 - t1;
            if (d < min_delta) {
                min_delta = d;
            }
        }
    }

    rep.min_cpuid_cycles = (min_delta == ~0ULL) ? 0ULL : min_delta;

    // Physical CPUs (and VBS Root Partition) complete CPUID in ~80..2500 cycles.
    // Software emulators / TCG / DBI frameworks take > 25000 cycles per CPUID exit.
    if (rep.min_cpuid_cycles > 25000ULL && rep.vendor != VmVendor::HostVbsOrRoot) {
        rep.flags |= VM_CPUID_TIMING_ANOMALY;
        if (rep.vendor == VmVendor::None) {
            rep.vendor = VmVendor::GenericGuest;
        }
    }
}

volatile LONG g_vm_cache_state = 0; // 0 = uninit, 1 = initializing, 2 = ready
VmReport      g_cached_vm_report{};

const VmReport& get_cached_static_vm_report() noexcept {
    LONG state = InterlockedCompareExchange(&g_vm_cache_state, 1, 0);
    if (state == 0) {
        VmReport rep{};
        check_cpuid_hypervisor(rep);
        check_smbios_firmware(rep);
        check_guest_devices(rep);
        check_vmware_io_port(rep);
        check_cpuid_timing(rep);
        g_cached_vm_report = rep;
        InterlockedExchange(&g_vm_cache_state, 2);
        return g_cached_vm_report;
    }
    while (InterlockedCompareExchange(&g_vm_cache_state, 2, 2) != 2) {
        _mm_pause();
    }
    return g_cached_vm_report;
}

} // namespace

VmReport run_all_vm_checks() noexcept {
    // Static hardware/firmware/device/port probes are executed once and cached;
    // lightweight zero-syscall CPUID leaf check runs live on every call.
    VmReport rep = get_cached_static_vm_report();
    check_cpuid_hypervisor(rep);
    return rep;
}

bool is_running_in_vm(VmReport* out_report) noexcept {
    const VmReport rep = run_all_vm_checks();
    if (out_report) {
        *out_report = rep;
    }
    return rep.is_virtual_machine();
}

uint64_t compute_vm_key_poison() noexcept {
    const VmReport rep = run_all_vm_checks();
    if (!rep.is_virtual_machine()) {
        return 0ULL;
    }
    const uint64_t f = static_cast<uint64_t>(rep.flags) * 0x9E3779B97F4A7C15ULL;
    const uint64_t v = static_cast<uint64_t>(rep.vendor) * 0xBF58476D1CE4E5B9ULL;
    return crypto::poly_permute_64(crypto::mba_xor(f, v), 0xD8B39A17E4C28F95ULL);
}

} // namespace vpack::antivm
