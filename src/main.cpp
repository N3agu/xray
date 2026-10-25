#include "core/mapped_file.hpp"
#include "core/report.hpp"
#include "pe/parser.hpp"
#include "analyzers/entropy.hpp"
#include "analyzers/iat.hpp"
#include "analyzers/syscalls.hpp"
#include "analyzers/strings.hpp"
#include "analyzers/deobfuscator.hpp"
#include "analyzers/anomalies.hpp"
#include "scoring/engine.hpp"
#include "output/reporter.hpp"
#include <fstream>
#include <iostream>
#include <string_view>

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
    std::cout << "General Options:\n";
    std::cout << "  -h, --help            Show this help message and exit\n";
    std::cout << "  -s, --silent          Suppress the banner and non-essential output\n";
    std::cout << "  -o, --output <file>   Write output report to specified file\n\n";
    std::cout << "Output Format Options:\n";
    std::cout << "  -j, --json            Emit results in JSON format\n";
    std::cout << "  -c, --csv             Emit results in CSV format\n";
    std::cout << "  -t, --text            Emit results in human-readable text format (default)\n\n";
    std::cout << "Selective Scan Filters (can be combined):\n";
    std::cout << "  --only-sections       Run only PE section & entropy analysis\n";
    std::cout << "  --only-iat            Run only Import Address Table & API triage\n";
    std::cout << "  --only-syscalls       Run only direct/indirect syscall stub detection\n";
    std::cout << "  --only-strings        Run only ASCII/UTF-16 string & artifact extraction\n";
    std::cout << "  --only-deobf          Run only XOR & Base64 string deobfuscation\n";
    std::cout << "  --only-anomalies      Run only TLS callback & overlay analysis\n\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        show_help(argv[0]);
        return 1;
    }

    xray::core::ScanOptions options;
    bool custom_filter_active = false;

    auto enable_selective = [&](bool& flag) {
        if (!custom_filter_active) {
            options.disable_all_scans();
            custom_filter_active = true;
        }
        flag = true;
    };

    for (int i = 1; i < argc; ++i) {
        std::string_view arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            show_help(argv[0]);
            return 0;
        } else if (arg == "-s" || arg == "--silent") {
            options.silent = true;
        } else if (arg == "-j" || arg == "--json") {
            options.format = xray::core::OutputFormat::Json;
        } else if (arg == "-c" || arg == "--csv") {
            options.format = xray::core::OutputFormat::Csv;
        } else if (arg == "-t" || arg == "--text") {
            options.format = xray::core::OutputFormat::Text;
        } else if (arg == "-o" || arg == "--output") {
            if (i + 1 >= argc) {
                std::cerr << "Error: --output requires a file path.\n";
                return 1;
            }
            options.output_file = argv[++i];
        } else if (arg == "--only-sections") {
            enable_selective(options.run_sections);
        } else if (arg == "--only-iat") {
            enable_selective(options.run_iat);
        } else if (arg == "--only-syscalls") {
            enable_selective(options.run_syscalls);
        } else if (arg == "--only-strings") {
            enable_selective(options.run_strings);
        } else if (arg == "--only-deobf") {
            enable_selective(options.run_deobf);
        } else if (arg == "--only-anomalies") {
            enable_selective(options.run_anomalies);
        } else if (arg.starts_with("-")) {
            std::cerr << "Unknown option: " << arg << "\n";
            show_help(argv[0]);
            return 1;
        } else {
            options.target_path = arg;
        }
    }

    if (options.target_path.empty()) {
        std::cerr << "Error: No input file specified.\n";
        show_help(argv[0]);
        return 1;
    }

    xray::core::MappedFile file(options.target_path);
    if (!file.is_valid()) {
        std::cerr << "[!] Failed to open or map file: " << options.target_path << "\n";
        return 1;
    }

    xray::pe::PeParser parser(file.span());
    if (!parser.is_valid()) {
        std::cerr << "[!] PE Parse Error: " << parser.error_message() << "\n";
        return 1;
    }

    xray::core::TriageReport report;
    report.filename = options.target_path.filename().string();
    report.file_size = file.size();
    report.is_64bit = parser.is_64bit();
    report.image_base = parser.image_base();
    report.entry_point_rva = parser.entry_point_rva();
    report.raw_sections = parser.sections();

    if (options.run_sections) {
        report.sections = xray::analyzers::SectionAnalyzer::analyze(parser);
    }
    if (options.run_iat) {
        report.iat = xray::analyzers::IatAnalyzer::analyze(parser);
    }
    if (options.run_syscalls) {
        report.syscalls = xray::analyzers::SyscallAnalyzer::analyze(parser);
    }
    if (options.run_strings) {
        report.strings = xray::analyzers::StringsAnalyzer::analyze(parser);
    }
    if (options.run_deobf) {
        report.deobfuscated = xray::analyzers::Deobfuscator::analyze(parser);
    }
    if (options.run_anomalies) {
        report.structural_anomalies = xray::analyzers::AnomaliesAnalyzer::analyze(parser);
    }

    report.risk = xray::scoring::RiskEngine::evaluate(
        report.sections,
        report.iat,
        report.syscalls,
        report.strings,
        report.deobfuscated,
        report.structural_anomalies
    );

    if (!options.output_file.empty()) {
        std::ofstream out_stream(options.output_file, std::ios::out | std::ios::trunc);
        if (!out_stream.is_open()) {
            std::cerr << "[!] Failed to open output file for writing: " << options.output_file << "\n";
            return 1;
        }
        xray::output::Reporter::render(report, options, out_stream, BANNER);
    } else {
        xray::output::Reporter::render(report, options, std::cout, BANNER);
    }

    return 0;
}