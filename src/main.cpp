#include "core/mapped_file.hpp"
#include "pe/parser.hpp"
#include "analyzers/entropy.hpp"
#include "analyzers/iat.hpp"
#include "analyzers/syscalls.hpp"
#include "analyzers/strings.hpp"
#include "analyzers/deobfuscator.hpp"
#include "scoring/engine.hpp"
#include <algorithm>
#include <iomanip>
#include <iostream>
#include <sstream>
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
    std::cout << "  -s, --silent   Suppress the banner and non-essential output\n";
    std::cout << "  -j, --json     Emit results in JSON format\n\n";
}

std::string format_permissions(uint32_t chars) {
    std::string perms;
    perms += (chars & xray::pe::SCN_MEM_READ)    ? 'R' : '-';
    perms += (chars & xray::pe::SCN_MEM_WRITE)   ? 'W' : '-';
    perms += (chars & xray::pe::SCN_MEM_EXECUTE) ? 'X' : '-';
    return perms;
}

std::string escape_json(std::string_view s) {
    std::ostringstream o;
    for (char c : s) {
        switch (c) {
            case '"':  o << "\\\""; break;
            case '\\': o << "\\\\"; break;
            case '\b': o << "\\b";  break;
            case '\f': o << "\\f";  break;
            case '\n': o << "\\n";  break;
            case '\r': o << "\\r";  break;
            case '\t': o << "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) <= 0x1f) {
                    o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(c) << std::dec << std::setfill(' ');
                } else {
                    o << c;
                }
        }
    }
    return o.str();
}

void emit_json(
    const std::filesystem::path& target_path,
    size_t file_size,
    const xray::pe::PeParser& parser,
    const std::vector<xray::analyzers::SectionAnalysis>& section_analyses,
    const xray::analyzers::IatAnalysisResult& iat_analysis,
    const std::vector<xray::analyzers::SyscallStub>& syscall_findings,
    const xray::analyzers::StringsAnalysisResult& strings_analysis,
    const xray::analyzers::DeobfuscationResult& deobfuscated,
    const xray::scoring::RiskReport& risk
) {
    std::cout << "{\n";
    std::cout << "  \"file\": {\n";
    std::cout << "    \"name\": \"" << escape_json(target_path.filename().string()) << "\",\n";
    std::cout << "    \"size\": " << file_size << ",\n";
    std::cout << "    \"is_64bit\": " << (parser.is_64bit() ? "true" : "false") << ",\n";
    std::cout << "    \"image_base\": " << parser.image_base() << ",\n";
    std::cout << "    \"entry_point_rva\": " << parser.entry_point_rva() << "\n";
    std::cout << "  },\n";

    std::cout << "  \"risk\": {\n";
    std::cout << "    \"score\": " << risk.total_score << ",\n";
    std::cout << "    \"level\": \"" << xray::scoring::RiskEngine::level_to_string(risk.level) << "\",\n";
    std::cout << "    \"triggered_rules\": [\n";
    for (size_t i = 0; i < risk.triggered_rules.size(); ++i) {
        const auto& r = risk.triggered_rules[i];
        std::cout << "      {\n";
        std::cout << "        \"rule\": \"" << escape_json(r.rule_name) << "\",\n";
        std::cout << "        \"points\": " << r.points << ",\n";
        std::cout << "        \"reason\": \"" << escape_json(r.reason) << "\"\n";
        std::cout << "      }" << (i + 1 < risk.triggered_rules.size() ? "," : "") << "\n";
    }
    std::cout << "    ]\n";
    std::cout << "  },\n";

    std::cout << "  \"sections\": [\n";
    for (size_t i = 0; i < parser.sections().size(); ++i) {
        const auto& sec = parser.sections()[i];
        const auto& sa = section_analyses[i];
        std::cout << "    {\n";
        std::cout << "      \"name\": \"" << escape_json(sec.name) << "\",\n";
        std::cout << "      \"virtual_address\": " << sec.virtual_address << ",\n";
        std::cout << "      \"virtual_size\": " << sec.virtual_size << ",\n";
        std::cout << "      \"raw_offset\": " << sec.raw_offset << ",\n";
        std::cout << "      \"raw_size\": " << sec.raw_size << ",\n";
        std::cout << "      \"entropy\": " << sa.entropy << ",\n";
        std::cout << "      \"permissions\": \"" << format_permissions(sec.characteristics) << "\"\n";
        std::cout << "    }" << (i + 1 < parser.sections().size() ? "," : "") << "\n";
    }
    std::cout << "  ],\n";

    std::cout << "  \"flagged_apis\": [\n";
    for (size_t i = 0; i < iat_analysis.suspicious_apis.size(); ++i) {
        const auto& api = iat_analysis.suspicious_apis[i];
        std::cout << "    {\n";
        std::cout << "      \"function\": \"" << escape_json(api.name) << "\",\n";
        std::cout << "      \"module\": \"" << escape_json(api.module_name) << "\",\n";
        std::cout << "      \"category\": \"" << escape_json(xray::analyzers::IatAnalyzer::category_to_string(api.category)) << "\",\n";
        std::cout << "      \"summary\": \"" << escape_json(api.threat_summary) << "\"\n";
        std::cout << "    }" << (i + 1 < iat_analysis.suspicious_apis.size() ? "," : "") << "\n";
    }
    std::cout << "  ],\n";

    std::cout << "  \"syscalls\": [\n";
    for (size_t i = 0; i < syscall_findings.size(); ++i) {
        const auto& sc = syscall_findings[i];
        std::cout << "    {\n";
        std::cout << "      \"type\": \"" << escape_json(xray::analyzers::SyscallAnalyzer::type_to_string(sc.type)) << "\",\n";
        std::cout << "      \"section\": \"" << escape_json(sc.section_name) << "\",\n";
        std::cout << "      \"rva\": " << sc.rva << ",\n";
        std::cout << "      \"file_offset\": " << sc.file_offset << ",\n";
        std::cout << "      \"ssn\": " << sc.ssn << "\n";
        std::cout << "    }" << (i + 1 < syscall_findings.size() ? "," : "") << "\n";
    }
    std::cout << "  ],\n";

    std::cout << "  \"artifacts\": [\n";
    for (size_t i = 0; i < strings_analysis.artifacts.size(); ++i) {
        const auto& art = strings_analysis.artifacts[i];
        std::cout << "    {\n";
        std::cout << "      \"offset\": " << art.offset << ",\n";
        std::cout << "      \"category\": \"" << escape_json(xray::analyzers::StringsAnalyzer::category_to_string(art.category)) << "\",\n";
        std::cout << "      \"value\": \"" << escape_json(art.value) << "\"\n";
        std::cout << "    }" << (i + 1 < strings_analysis.artifacts.size() ? "," : "") << "\n";
    }
    std::cout << "  ],\n";

    std::cout << "  \"deobfuscated\": [\n";
    for (size_t i = 0; i < deobfuscated.findings.size(); ++i) {
        const auto& item = deobfuscated.findings[i];
        std::cout << "    {\n";
        std::cout << "      \"offset\": " << item.offset << ",\n";
        std::cout << "      \"method\": \"" << escape_json(xray::analyzers::Deobfuscator::type_to_string(item.type)) << "\",\n";
        std::cout << "      \"key\": " << item.key << ",\n";
        std::cout << "      \"decoded_value\": \"" << escape_json(item.decoded_value) << "\"\n";
        std::cout << "    }" << (i + 1 < deobfuscated.findings.size() ? "," : "") << "\n";
    }
    std::cout << "  ]\n";
    std::cout << "}\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        show_help(argv[0]);
        return 1;
    }

    bool silent = false;
    bool json_mode = false;
    std::filesystem::path target_path;

    for (int i = 1; i < argc; ++i) {
        std::string_view arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            show_help(argv[0]);
            return 0;
        } else if (arg == "-s" || arg == "--silent") {
            silent = true;
        } else if (arg == "-j" || arg == "--json") {
            json_mode = true;
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
    auto strings_analysis = xray::analyzers::StringsAnalyzer::analyze(parser);
    auto deobfuscated = xray::analyzers::Deobfuscator::analyze(parser);

    auto risk = xray::scoring::RiskEngine::evaluate(
        section_analyses,
        iat_analysis,
        syscall_findings,
        strings_analysis,
        deobfuscated
    );

    if (json_mode) {
        emit_json(target_path, file.size(), parser, section_analyses, iat_analysis, syscall_findings, strings_analysis, deobfuscated, risk);
        return 0;
    }

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

    std::cout << "\nStrings Summary:\n";
    std::cout << "  Total Extracted: " << strings_analysis.total_strings_found << "\n";

    if (!strings_analysis.artifacts.empty()) {
        std::cout << "\nHigh-Signal Artifacts Detected:\n";
        std::cout << std::left
                  << std::setw(12) << "Offset"
                  << std::setw(22) << "Category"
                  << "Value\n";
        std::cout << std::string(72, '-') << "\n";

        for (const auto& artifact : strings_analysis.artifacts) {
            std::cout << std::left
                      << "0x" << std::hex << std::setw(10) << artifact.offset << std::dec
                      << std::setw(22) << xray::analyzers::StringsAnalyzer::category_to_string(artifact.category)
                      << artifact.value << "\n";
        }
    }

    if (!deobfuscated.findings.empty()) {
        std::cout << "\nDeobfuscated Strings Recovered:\n";
        std::cout << std::left
                  << std::setw(12) << "Offset"
                  << std::setw(16) << "Method"
                  << std::setw(10) << "Key"
                  << "Decoded Value\n";
        std::cout << std::string(72, '-') << "\n";

        for (const auto& item : deobfuscated.findings) {
            std::cout << std::left
                      << "0x" << std::hex << std::setw(10) << item.offset
                      << std::setw(16) << xray::analyzers::Deobfuscator::type_to_string(item.type);
            if (item.type == xray::analyzers::DeobfuscationType::Base64) {
                std::cout << std::setw(10) << "-";
            } else {
                std::cout << "0x" << std::hex << std::setw(8) << item.key;
            }
            std::cout << std::dec << item.decoded_value << "\n";
        }
    }

    std::cout << "\nRisk Evaluation:\n";
    std::cout << "  Score: " << risk.total_score << " / 100\n";
    std::cout << "  Level: " << xray::scoring::RiskEngine::level_to_string(risk.level) << "\n";

    if (!risk.triggered_rules.empty()) {
        std::cout << "\nTriggered Threat Indicators:\n";
        std::cout << std::left
                  << std::setw(32) << "Rule"
                  << std::setw(10) << "Points"
                  << "Reason\n";
        std::cout << std::string(76, '-') << "\n";

        for (const auto& r : risk.triggered_rules) {
            std::cout << std::left
                      << std::setw(32) << r.rule_name
                      << std::setw(10) << ("+" + std::to_string(r.points))
                      << r.reason << "\n";
        }
    }

    return 0;
}