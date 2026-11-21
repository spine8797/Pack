#pragma once

#include "vpack/config.h"
#include <cstdint>

namespace vpack::antivm {

enum VmFlag : uint32_t {
    VM_NONE                     = 0,
    VM_CPUID_HYPERVISOR_VENDOR  = 1u << 0, // VMware / VBox / KVM / QEMU / Xen / Parallels CPUID leaf
    VM_SMBIOS_FIRMWARE          = 1u << 1, // Virtual machine manufacturer/product in raw RSMB firmware
    VM_GUEST_DEVICE_DRIVER      = 1u << 2, // Kernel guest driver device object (\??\vmci, \??\VBoxGuest, ...)
    VM_VMWARE_IO_PORT           = 1u << 3, // VMware 0x5658 ('VX') ring -1 backdoor port responded
    VM_HYPERV_GUEST_PARTITION   = 1u << 4, // Child Hyper-V guest VM (excludes Host Root / VBS physical PC)
    VM_CPUID_TIMING_ANOMALY     = 1u << 5  // Extreme VM-Exit / TCG / DBI cycle latency on CPUID
};

enum class VmVendor : uint8_t {
    None = 0,
    HostVbsOrRoot, // Physical Windows PC running VBS / Core Isolation / Hyper-V Root (SAFE)
    VMware,
    VirtualBox,
    QEMU,
    KVM,
    Xen,
    Parallels,
    Bhyve,
    HyperVGuest,
    GenericGuest
};

struct VmReport {
    uint32_t flags          = VM_NONE;
    VmVendor vendor         = VmVendor::None;
    uint64_t min_cpuid_cycles = 0;
    bool     hypervisor_bit = false;

    bool is_virtual_machine() const noexcept { return flags != VM_NONE; }
};

VmReport run_all_vm_checks() noexcept;

bool is_running_in_vm(VmReport* out_report = nullptr) noexcept;

// Returns 0ULL on physical hardware (including Windows 11 Host with VBS/WSL2),
// or a non-zero cryptographic key poison when inside VMware/VBox/QEMU/KVM/Guest VM.
uint64_t compute_vm_key_poison() noexcept;

} // namespace vpack::antivm
