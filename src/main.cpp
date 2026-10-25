#include "core/mapped_file.hpp"
#include "pe/parser.hpp"
#include "analyzers/entropy.hpp"
#include "analyzers/iat.hpp"
#include "analyzers/syscalls.hpp"
#include <algorithm>
#include <iomanip>
#include <iostream>
#include <string_view>
#include <vector>

const char* BANNER = R"(__  ___ __ __ _ _   _ 
\ \/ / '__/ _` | | | |
 >  <| | | (_| | |_| |
/_/\_\_|  \__,_|\__, |
                |___/ 
github.com/N3agu/xray
)";

void show_help(std::string_view program_name) {
    std::cout << BANNER << "\n";
    std::cout << "Usage: " << program_name << " [options] <path_to_pe_binary>\n\n";
    std::cout << "Options:\n";
    std::cout << "  -h, --help     Show this help message and exit\n";
    std::cout << "  -s, --silent   Suppress the banner and non-essential output\n\n";
}

std::string format_permissions(uint32_t chars) {
    std::string perms;
    perms += (chars & xray::pe::SCN_MEM_READ)    ? 'R' : '-';
    perms += (chars & xray::pe::SCN_MEM_WRITE)   ? 'W' : '-';
    perms += (chars & xray::pe::SCN_MEM_EXECUTE) ? 'X' : '-';
    return perms;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        show_help(argv[0]);
        return 1;
    }

    bool silent = false;
    std::filesystem::path target_path;

    for (int i = 1; i < argc; ++i) {
        std::string_view arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            show_help(argv[0]);
            return 0;
        } else if (arg == "-s" || arg == "--silent") {
            silent = true;
        } else if (arg.starts_with("-")) {
            std::cerr << "Unknown option: " << arg << "\n";
            show_help(argv[0]);
            return 1;
        } else {
            target_path = arg;
        }
    }

    if (target_path.empty()) {
        std::cerr << "Error: No input file specified.\n";
        show_help(argv[0]);
        return 1;
    }

    xray::core::MappedFile file(target_path);
    if (!file.is_valid()) {
        std::cerr << "[!] Failed to open or map file: " << target_path << "\n";
        return 1;
    }

    xray::pe::PeParser parser(file.span());
    if (!parser.is_valid()) {
        std::cerr << "[!] PE Parse Error: " << parser.error_message() << "\n";
        return 1;
    }

    auto section_analyses = xray::analyzers::SectionAnalyzer::analyze(parser);
    auto iat_analysis = xray::analyzers::IatAnalyzer::analyze(parser);
    auto syscall_findings = xray::analyzers::SyscallAnalyzer::analyze(parser);

    if (!silent) {
        std::cout << BANNER << "\n";
        std::cout << "Static Binary Triage:\n";
        std::cout << "File:         " << target_path.filename().string() << "\n";
        std::cout << "Size:         " << file.size() << " bytes\n";
        std::cout << "Architecture: " << (parser.is_64bit() ? "x64 (PE32+)" : "x86 (PE32)") << "\n";
        std::cout << "Image Base:   0x" << std::hex << parser.image_base() << "\n";
        std::cout << "Entry Point:  0x" << std::hex << parser.entry_point_rva() << std::dec << "\n\n";
    }

    std::cout << std::left
              << std::setw(10) << "Name"
              << std::setw(12) << "VirtAddr"
              << std::setw(12) << "VirtSize"
              << std::setw(12) << "RawAddr"
              << std::setw(12) << "RawSize"
              << std::setw(8)  << "Entropy"
              << std::setw(6)  << "Perms" << "\n";
    std::cout << std::string(72, '-') << "\n";

    for (size_t i = 0; i < parser.sections().size(); ++i) {
        const auto& sec = parser.sections()[i];
        const auto& analysis = section_analyses[i];

        std::cout << std::left << std::setw(10) << sec.name
                  << "0x" << std::hex << std::setw(10) << sec.virtual_address
                  << "0x" << std::setw(10) << sec.virtual_size
                  << "0x" << std::setw(10) << sec.raw_offset
                  << "0x" << std::setw(10) << sec.raw_size
                  << std::dec << std::fixed << std::setprecision(2) << std::setw(8) << analysis.entropy
                  << std::setw(6) << format_permissions(sec.characteristics)
                  << "\n";
    }

    std::vector<xray::analyzers::SectionAnomaly> all_anomalies;
    for (const auto& analysis : section_analyses) {
        for (const auto& anomaly : analysis.anomalies) {
            all_anomalies.push_back(anomaly);
        }
    }

    if (!all_anomalies.empty()) {
        std::cout << "\nSection Anomalies:\n";
        for (const auto& anomaly : all_anomalies) {
            std::cout << "  [" << (anomaly.is_critical ? "CRITICAL" : "WARNING") << "] "
                      << anomaly.section_name << ": " << anomaly.description << "\n";
        }
    }

    std::cout << "\nImports Summary:\n";
    std::cout << "  Total Modules: " << iat_analysis.libraries.size() << "\n";
    std::cout << "  Total Imports: " << iat_analysis.total_import_count << "\n";

    if (iat_analysis.low_import_count_anomaly) {
        std::cout << "  [WARNING] Abnormally low import count (< 5) - possible packer or runtime resolution\n";
    }

    if (!iat_analysis.suspicious_apis.empty()) {
        size_t max_func_len = 8;
        size_t max_mod_len = 6;
        size_t max_cat_len = 8;

        for (const auto& api : iat_analysis.suspicious_apis) {
            max_func_len = std::max(max_func_len, api.name.length());
            max_mod_len = std::max(max_mod_len, api.module_name.length());
            max_cat_len = std::max(max_cat_len, xray::analyzers::IatAnalyzer::category_to_string(api.category).length());
        }

        max_func_len += 2;
        max_mod_len += 2;
        max_cat_len += 2;

        std::cout << "\nTriage Flagged APIs:\n";
        std::cout << std::left
                  << std::setw(max_func_len) << "Function"
                  << std::setw(max_mod_len)  << "Module"
                  << std::setw(max_cat_len)  << "Category"
                  << "Summary\n";
        std::cout << std::string(max_func_len + max_mod_len + max_cat_len + 35, '-') << "\n";

        for (const auto& api : iat_analysis.suspicious_apis) {
            std::cout << std::left
                      << std::setw(max_func_len) << api.name
                      << std::setw(max_mod_len)  << api.module_name
                      << std::setw(max_cat_len)  << xray::analyzers::IatAnalyzer::category_to_string(api.category)
                      << api.threat_summary << "\n";
        }
    }

    if (!syscall_findings.empty()) {
        std::cout << "\nEvasive Syscall Stubs Detected:\n";
        std::cout << std::left
                  << std::setw(20) << "Type"
                  << std::setw(10) << "Section"
                  << std::setw(12) << "RVA"
                  << std::setw(12) << "FileOffset"
                  << "SSN\n";
        std::cout << std::string(62, '-') << "\n";

        for (const auto& sc : syscall_findings) {
            std::cout << std::left
                      << std::setw(20) << xray::analyzers::SyscallAnalyzer::type_to_string(sc.type)
                      << std::setw(10) << sc.section_name
                      << "0x" << std::hex << std::setw(10) << sc.rva
                      << "0x" << std::setw(10) << sc.file_offset
                      << "0x" << sc.ssn << std::dec << "\n";
        }
    }

    return 0;
}