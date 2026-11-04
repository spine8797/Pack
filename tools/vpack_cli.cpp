#include "vpack/vpack.h"
#include <iostream>
#include <iomanip>
#include <string>

namespace {

void print_usage(const char* prog) {
    std::cout << "============================================================\n"
              << "  VPack PE64 Protection CLI\n"
              << "============================================================\n"
              << "Usage:\n"
              << "  " << prog << " inspect <input.exe>\n"
              << "  " << prog << " pack    <input.exe> <output.exe> [--no-anti-debug] [--seed <hex>]\n";
}

int cmd_inspect(const std::string& input_path) {
    vpack::pe::PeImage img;
    std::string err;
    if (!img.load_from_file(input_path, &err)) {
        std::cerr << "[!] Error: " << err << "\n";
        return 1;
    }

    std::cout << "[+] File           : " << input_path << "\n"
              << "[+] ImageBase      : 0x" << std::hex << img.image_base() << "\n"
              << "[+] EntryPoint RVA : 0x" << std::hex << img.entry_point_rva() << "\n"
              << "[+] SizeOfImage    : 0x" << std::hex << img.size_of_image() << "\n";

    vpack::VPackHeader vhdr{};
    if (img.is_already_packed(&vhdr)) {
        std::cout << "[+] Packed Status  : PACKED (.vpack detected)\n"
                  << "    Original OEP   : 0x" << std::hex << vhdr.original_entry_rva << "\n"
                  << "    Encrypted Regs : " << std::dec << vhdr.region_count << "\n"
                  << "    Master Seed    : 0x" << std::hex << vhdr.master_seed << "\n";
    } else {
        std::cout << "[+] Packed Status  : UNPACKED\n";
    }

    std::cout << "\nSections:\n"
              << "  " << std::left << std::setw(10) << "Name"
              << std::setw(14) << "VirtAddr"
              << std::setw(14) << "VirtSize"
              << std::setw(14) << "RawOffset"
              << std::setw(14) << "RawSize"
              << "Characteristics\n"
              << "  --------------------------------------------------------------------------\n";

    for (const auto& s : img.list_sections()) {
        std::cout << "  " << std::left << std::setw(10) << s.name
                  << "0x" << std::hex << std::setw(12) << s.virtual_address
                  << "0x" << std::hex << std::setw(12) << s.virtual_size
                  << "0x" << std::hex << std::setw(12) << s.raw_offset
                  << "0x" << std::hex << std::setw(12) << s.raw_size
                  << "0x" << std::hex << s.characteristics << std::dec << "\n";
    }
    return 0;
}

int cmd_pack(int argc, char** argv) {
    if (argc < 4) {
        print_usage(argv[0]);
        return 1;
    }

    std::string input_path  = argv[2];
    std::string output_path = argv[3];

    vpack::pe::PackOptions opts{};
    for (int i = 4; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--no-anti-debug") {
            opts.stub_anti_debug = false;
        } else if (arg == "--seed" && i + 1 < argc) {
            opts.custom_seed = std::stoull(argv[++i], nullptr, 0);
        }
    }

    vpack::pe::PeImage img;
    std::string err;
    if (!img.load_from_file(input_path, &err)) {
        std::cerr << "[!] Load failed: " << err << "\n";
        return 1;
    }

    auto res = img.pack(opts);
    if (!res.success) {
        std::cerr << "[!] Pack failed: " << res.message << "\n";
        return 1;
    }

    if (!img.save_to_file(output_path, &err)) {
        std::cerr << "[!] Save failed: " << err << "\n";
        return 1;
    }

    std::cout << "[+] " << res.message << "\n"
              << "    Input File         : " << input_path << "\n"
              << "    Output File        : " << output_path << "\n"
              << "    Original OEP RVA   : 0x" << std::hex << res.original_entry_rva << "\n"
              << "    New Stub Entry RVA : 0x" << std::hex << res.new_entry_rva << "\n"
              << "    Encrypted Regions  : " << std::dec << res.encrypted_regions << " (.text, .vcode, .pdata)\n"
              << "    Stripped Sections  : " << res.stripped_sections << " debug/symbol sections\n"
              << "    Output Size        : " << res.output_size << " bytes\n";
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }

    std::string mode = argv[1];
    if (mode == "inspect") {
        return cmd_inspect(argv[2]);
    }
    if (mode == "pack") {
        return cmd_pack(argc, argv);
    }

    print_usage(argv[0]);
    return 1;
}
