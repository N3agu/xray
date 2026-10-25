#include "output/reporter.hpp"
#include <algorithm>
#include <iomanip>
#include <sstream>

namespace xray::output {

std::string Reporter::format_permissions(uint32_t chars) {
    std::string perms;
    perms += (chars & pe::SCN_MEM_READ)    ? 'R' : '-';
    perms += (chars & pe::SCN_MEM_WRITE)   ? 'W' : '-';
    perms += (chars & pe::SCN_MEM_EXECUTE) ? 'X' : '-';
    return perms;
}

std::string Reporter::escape_json(std::string_view s) {
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

std::string Reporter::escape_csv(std::string_view s) {
    std::string out = "\"";
    for (char c : s) {
        if (c == '"') {
            out += "\"\"";
        } else if (c >= 0x20 && c <= 0x7E) {
            out += c;
        }
    }
    out += "\"";
    return out;
}

void Reporter::render(
    const core::TriageReport& report,
    const core::ScanOptions& options,
    std::ostream& out,
    std::string_view banner
) {
    switch (options.format) {
        case core::OutputFormat::Text:
            render_text(report, options, out, banner);
            break;
        case core::OutputFormat::Json:
            render_json(report, options, out);
            break;
        case core::OutputFormat::Csv:
            render_csv(report, options, out);
            break;
    }
}

void Reporter::render_text(
    const core::TriageReport& report,
    const core::ScanOptions& options,
    std::ostream& out,
    std::string_view banner
) {
    const auto& sa = report.structural_anomalies;

    if (!options.silent) {
        out << banner << "\n";
        out << "Static Binary Triage:\n";
        out << "File:         " << report.filename << "\n";
        out << "Size:         " << report.file_size << " bytes\n";
        out << "Architecture: " << (report.is_64bit ? "x64 (PE32+)" : "x86 (PE32)") << "\n";
        out << "Image Base:   0x" << std::hex << report.image_base << "\n";
        out << "Entry Point:  0x" << std::hex << report.entry_point_rva << std::dec
            << " (" << (sa.ep_section_name.empty() ? "Unknown" : sa.ep_section_name) << ")\n";
        out << "Mitigations:  "
            << "ASLR=" << (sa.aslr_enabled ? "ON " : "OFF ")
            << "DEP=" << (sa.dep_enabled ? "ON " : "OFF ")
            << "CFG=" << (sa.cfg_enabled ? "ON " : "OFF ")
            << "Signed=" << (sa.is_signed ? "YES" : "NO") << "\n\n";
    }

    if (options.run_sections) {
        out << std::left
            << std::setw(10) << "Name"
            << std::setw(12) << "VirtAddr"
            << std::setw(12) << "VirtSize"
            << std::setw(12) << "RawAddr"
            << std::setw(12) << "RawSize"
            << std::setw(8)  << "Entropy"
            << std::setw(6)  << "Perms" << "\n";
        out << std::string(72, '-') << "\n";

        for (size_t i = 0; i < report.raw_sections.size() && i < report.sections.size(); ++i) {
            const auto& sec = report.raw_sections[i];
            const auto& analysis = report.sections[i];

            out << std::left << std::setw(10) << sec.name
                << "0x" << std::hex << std::setw(10) << sec.virtual_address
                << "0x" << std::setw(10) << sec.virtual_size
                << "0x" << std::setw(10) << sec.raw_offset
                << "0x" << std::setw(10) << sec.raw_size
                << std::dec << std::fixed << std::setprecision(2) << std::setw(8) << analysis.entropy
                << std::setw(6) << format_permissions(sec.characteristics)
                << "\n";
        }

        std::vector<analyzers::SectionAnomaly> all_anomalies;
        for (const auto& analysis : report.sections) {
            for (const auto& anomaly : analysis.anomalies) {
                all_anomalies.push_back(anomaly);
            }
        }

        if (!all_anomalies.empty()) {
            out << "\nSection Anomalies:\n";
            for (const auto& anomaly : all_anomalies) {
                out << "  [" << (anomaly.is_critical ? "CRITICAL" : "WARNING") << "] "
                    << anomaly.section_name << ": " << anomaly.description << "\n";
            }
        }
    }

    if (options.run_anomalies) {
        if (sa.ep_outside_text || sa.ep_in_last_section || sa.timestamp_anomaly || !sa.non_standard_sections.empty()) {
            out << "\nStructural & Header Anomalies:\n";
            if (sa.ep_outside_text) {
                out << "  [WARNING] Entry Point resides outside standard .text section (" << sa.ep_section_name << ")\n";
            }
            if (sa.ep_in_last_section) {
                out << "  [WARNING] Entry Point resides in the final section (" << sa.ep_section_name << ")\n";
            }
            if (sa.timestamp_anomaly) {
                out << "  [WARNING] " << sa.timestamp_note << "\n";
            }
            if (!sa.non_standard_sections.empty()) {
                out << "  [INFO]    Non-standard section names: ";
                for (size_t i = 0; i < sa.non_standard_sections.size(); ++i) {
                    out << sa.non_standard_sections[i] << (i + 1 < sa.non_standard_sections.size() ? ", " : "\n");
                }
            }
        }

        if (sa.overlay.present) {
            out << "\nOverlay Detected:\n";
            out << "  Offset:  0x" << std::hex << sa.overlay.offset << std::dec << "\n";
            out << "  Size:    " << sa.overlay.size << " bytes\n";
            out << "  Entropy: " << std::fixed << std::setprecision(2) << sa.overlay.entropy << "\n";
        }

        if (!sa.tls_callbacks.empty()) {
            out << "\nTLS Callbacks Registered:\n";
            out << std::left
                << std::setw(20) << "VirtualAddress"
                << std::setw(14) << "RVA"
                << "FileOffset\n";
            out << std::string(48, '-') << "\n";

            for (const auto& cb : sa.tls_callbacks) {
                out << std::left
                    << "0x" << std::hex << std::setw(18) << cb.va
                    << "0x" << std::setw(12) << cb.rva
                    << "0x" << cb.file_offset << std::dec << "\n";
            }
        }

        if (!sa.exports.exported_functions.empty()) {
            out << "\nExports Summary (" << (sa.exports.dll_name.empty() ? "Unnamed" : sa.exports.dll_name) << "):\n";
            out << "  Total Exported Functions: " << sa.exports.exported_functions.size() << "\n";
            if (!sa.exports.suspicious_exports.empty()) {
                for (const auto& sexp : sa.exports.suspicious_exports) {
                    out << "  [CRITICAL] Suspicious Loader Export: " << sexp << "\n";
                }
            }
        }
    }

    if (options.run_iat) {
        out << "\nImports Summary:\n";
        out << "  Total Modules: " << report.iat.libraries.size() << "\n";
        out << "  Total Imports: " << report.iat.total_import_count << "\n";

        if (report.iat.low_import_count_anomaly) {
            out << "  [WARNING] Abnormally low import count (< 5) - possible packer or runtime resolution\n";
        }

        if (!report.iat.suspicious_apis.empty()) {
            size_t max_func_len = 8;
            size_t max_mod_len = 6;
            size_t max_cat_len = 8;

            for (const auto& api : report.iat.suspicious_apis) {
                max_func_len = std::max(max_func_len, api.name.length());
                max_mod_len = std::max(max_mod_len, api.module_name.length());
                max_cat_len = std::max(max_cat_len, analyzers::IatAnalyzer::category_to_string(api.category).length());
            }

            // Add 2 spaces of padding between columns
            max_func_len += 2;
            max_mod_len += 2;
            max_cat_len += 2;

            out << "\nTriage Flagged APIs:\n";
            out << std::left
                << std::setw(max_func_len) << "Function"
                << std::setw(max_mod_len)  << "Module"
                << std::setw(max_cat_len)  << "Category"
                << "Summary\n";
            out << std::string(max_func_len + max_mod_len + max_cat_len + 35, '-') << "\n";

            for (const auto& api : report.iat.suspicious_apis) {
                out << std::left
                    << std::setw(max_func_len) << api.name
                    << std::setw(max_mod_len)  << api.module_name
                    << std::setw(max_cat_len)  << analyzers::IatAnalyzer::category_to_string(api.category)
                    << api.threat_summary << "\n";
            }
        }
    }

    if (options.run_syscalls && !report.syscalls.empty()) {
        out << "\nLow-Level Code & Syscall Stubs Detected:\n";
        out << std::left
            << std::setw(22) << "Type"
            << std::setw(10) << "Section"
            << std::setw(12) << "RVA"
            << std::setw(12) << "FileOffset"
            << "SSN\n";
        out << std::string(64, '-') << "\n";

        for (const auto& sc : report.syscalls) {
            out << std::left
                << std::setw(22) << analyzers::SyscallAnalyzer::type_to_string(sc.type)
                << std::setw(10) << sc.section_name
                << "0x" << std::hex << std::setw(10) << sc.rva
                << "0x" << std::setw(10) << sc.file_offset;
            if (sc.type == analyzers::SyscallType::Direct || sc.type == analyzers::SyscallType::Indirect) {
                out << "0x" << sc.ssn << std::dec << "\n";
            } else {
                out << std::dec << "-\n";
            }
        }
    }

    if (options.run_strings) {
        out << "\nStrings Summary:\n";
        out << "  Total Extracted: " << report.strings.total_strings_found << "\n";

        if (!report.strings.artifacts.empty()) {
            out << "\nHigh-Signal Artifacts Detected:\n";
            out << std::left
                << std::setw(12) << "Offset"
                << std::setw(22) << "Category"
                << "Value\n";
            out << std::string(72, '-') << "\n";

            for (const auto& artifact : report.strings.artifacts) {
                out << std::left
                    << "0x" << std::hex << std::setw(10) << artifact.offset << std::dec
                    << std::setw(22) << analyzers::StringsAnalyzer::category_to_string(artifact.category)
                    << artifact.value << "\n";
            }
        }
    }

    if (options.run_deobf && !report.deobfuscated.findings.empty()) {
        out << "\nDeobfuscated Strings Recovered:\n";
        out << std::left
            << std::setw(12) << "Offset"
            << std::setw(18) << "Method"
            << std::setw(10) << "Key"
            << "Decoded Value\n";
        out << std::string(74, '-') << "\n";

        for (const auto& item : report.deobfuscated.findings) {
            out << std::left
                << "0x" << std::hex << std::setw(10) << item.offset
                << std::setw(18) << analyzers::Deobfuscator::type_to_string(item.type);
            if (item.type == analyzers::DeobfuscationType::Base64) {
                out << std::setw(10) << "-";
            } else {
                out << "0x" << std::hex << std::setw(8) << item.key;
            }
            out << std::dec << item.decoded_value << "\n";
        }
    }

    out << "\nRisk Evaluation:\n";
    out << "  Score: " << report.risk.total_score << " / 100\n";
    out << "  Level: " << scoring::RiskEngine::level_to_string(report.risk.level) << "\n";

    if (!report.risk.triggered_rules.empty()) {
        out << "\nTriggered Threat Indicators:\n";
        out << std::left
            << std::setw(32) << "Rule"
            << std::setw(10) << "Points"
            << "Reason\n";
        out << std::string(76, '-') << "\n";

        for (const auto& r : report.risk.triggered_rules) {
            out << std::left
                << std::setw(32) << r.rule_name
                << std::setw(10) << ("+" + std::to_string(r.points))
                << r.reason << "\n";
        }
    }
}

void Reporter::render_json(const core::TriageReport& report, const core::ScanOptions&, std::ostream& out) {
    const auto& sa = report.structural_anomalies;
    out << "{\n";
    out << "  \"file\": {\n";
    out << "    \"name\": \"" << escape_json(report.filename) << "\",\n";
    out << "    \"size\": " << report.file_size << ",\n";
    out << "    \"is_64bit\": " << (report.is_64bit ? "true" : "false") << ",\n";
    out << "    \"image_base\": " << report.image_base << ",\n";
    out << "    \"entry_point_rva\": " << report.entry_point_rva << ",\n";
    out << "    \"entry_point_section\": \"" << escape_json(sa.ep_section_name) << "\",\n";
    out << "    \"aslr\": " << (sa.aslr_enabled ? "true" : "false") << ",\n";
    out << "    \"dep\": " << (sa.dep_enabled ? "true" : "false") << ",\n";
    out << "    \"cfg\": " << (sa.cfg_enabled ? "true" : "false") << ",\n";
    out << "    \"signed\": " << (sa.is_signed ? "true" : "false") << "\n";
    out << "  },\n";

    out << "  \"risk\": {\n";
    out << "    \"score\": " << report.risk.total_score << ",\n";
    out << "    \"level\": \"" << scoring::RiskEngine::level_to_string(report.risk.level) << "\",\n";
    out << "    \"triggered_rules\": [\n";
    for (size_t i = 0; i < report.risk.triggered_rules.size(); ++i) {
        const auto& r = report.risk.triggered_rules[i];
        out << "      {\n";
        out << "        \"rule\": \"" << escape_json(r.rule_name) << "\",\n";
        out << "        \"points\": " << r.points << ",\n";
        out << "        \"reason\": \"" << escape_json(r.reason) << "\"\n";
        out << "      }" << (i + 1 < report.risk.triggered_rules.size() ? "," : "") << "\n";
    }
    out << "    ]\n";
    out << "  },\n";

    out << "  \"overlay\": {\n";
    out << "    \"present\": " << (sa.overlay.present ? "true" : "false") << ",\n";
    out << "    \"offset\": " << sa.overlay.offset << ",\n";
    out << "    \"size\": " << sa.overlay.size << ",\n";
    out << "    \"entropy\": " << std::fixed << std::setprecision(2) << sa.overlay.entropy << "\n";
    out << "  },\n";

    out << "  \"tls_callbacks\": [\n";
    for (size_t i = 0; i < sa.tls_callbacks.size(); ++i) {
        const auto& cb = sa.tls_callbacks[i];
        out << "    {\n";
        out << "      \"va\": " << cb.va << ",\n";
        out << "      \"rva\": " << cb.rva << ",\n";
        out << "      \"file_offset\": " << cb.file_offset << "\n";
        out << "    }" << (i + 1 < sa.tls_callbacks.size() ? "," : "") << "\n";
    }
    out << "  ],\n";

    out << "  \"sections\": [\n";
    for (size_t i = 0; i < report.raw_sections.size() && i < report.sections.size(); ++i) {
        const auto& sec = report.raw_sections[i];
        const auto& sec_an = report.sections[i];
        out << "    {\n";
        out << "      \"name\": \"" << escape_json(sec.name) << "\",\n";
        out << "      \"virtual_address\": " << sec.virtual_address << ",\n";
        out << "      \"virtual_size\": " << sec.virtual_size << ",\n";
        out << "      \"raw_offset\": " << sec.raw_offset << ",\n";
        out << "      \"raw_size\": " << sec.raw_size << ",\n";
        out << "      \"entropy\": " << sec_an.entropy << ",\n";
        out << "      \"permissions\": \"" << format_permissions(sec.characteristics) << "\"\n";
        out << "    }" << (i + 1 < report.sections.size() ? "," : "") << "\n";
    }
    out << "  ],\n";

    out << "  \"flagged_apis\": [\n";
    for (size_t i = 0; i < report.iat.suspicious_apis.size(); ++i) {
        const auto& api = report.iat.suspicious_apis[i];
        out << "    {\n";
        out << "      \"function\": \"" << escape_json(api.name) << "\",\n";
        out << "      \"module\": \"" << escape_json(api.module_name) << "\",\n";
        out << "      \"category\": \"" << escape_json(analyzers::IatAnalyzer::category_to_string(api.category)) << "\",\n";
        out << "      \"summary\": \"" << escape_json(api.threat_summary) << "\"\n";
        out << "    }" << (i + 1 < report.iat.suspicious_apis.size() ? "," : "") << "\n";
    }
    out << "  ],\n";

    out << "  \"syscalls\": [\n";
    for (size_t i = 0; i < report.syscalls.size(); ++i) {
        const auto& sc = report.syscalls[i];
        out << "    {\n";
        out << "      \"type\": \"" << escape_json(analyzers::SyscallAnalyzer::type_to_string(sc.type)) << "\",\n";
        out << "      \"section\": \"" << escape_json(sc.section_name) << "\",\n";
        out << "      \"rva\": " << sc.rva << ",\n";
        out << "      \"file_offset\": " << sc.file_offset << ",\n";
        out << "      \"ssn\": " << sc.ssn << "\n";
        out << "    }" << (i + 1 < report.syscalls.size() ? "," : "") << "\n";
    }
    out << "  ],\n";

    out << "  \"artifacts\": [\n";
    for (size_t i = 0; i < report.strings.artifacts.size(); ++i) {
        const auto& art = report.strings.artifacts[i];
        out << "    {\n";
        out << "      \"offset\": " << art.offset << ",\n";
        out << "      \"category\": \"" << escape_json(analyzers::StringsAnalyzer::category_to_string(art.category)) << "\",\n";
        out << "      \"value\": \"" << escape_json(art.value) << "\"\n";
        out << "    }" << (i + 1 < report.strings.artifacts.size() ? "," : "") << "\n";
    }
    out << "  ],\n";

    out << "  \"deobfuscated\": [\n";
    for (size_t i = 0; i < report.deobfuscated.findings.size(); ++i) {
        const auto& item = report.deobfuscated.findings[i];
        out << "    {\n";
        out << "      \"offset\": " << item.offset << ",\n";
        out << "      \"method\": \"" << escape_json(analyzers::Deobfuscator::type_to_string(item.type)) << "\",\n";
        out << "      \"key\": " << item.key << ",\n";
        out << "      \"decoded_value\": \"" << escape_json(item.decoded_value) << "\"\n";
        out << "    }" << (i + 1 < report.deobfuscated.findings.size() ? "," : "") << "\n";
    }
    out << "  ]\n";
    out << "}\n";
}

void Reporter::render_csv(const core::TriageReport& report, const core::ScanOptions&, std::ostream& out) {
    out << "Category,Identifier,Location,Details\n";

    for (size_t i = 0; i < report.raw_sections.size() && i < report.sections.size(); ++i) {
        const auto& sec = report.raw_sections[i];
        const auto& sa = report.sections[i];
        std::ostringstream det;
        det << "Entropy=" << std::fixed << std::setprecision(2) << sa.entropy
            << " Perms=" << format_permissions(sec.characteristics);
        out << "Section," << escape_csv(sec.name) << ",0x" << std::hex << sec.virtual_address << std::dec << "," << escape_csv(det.str()) << "\n";
    }

    if (report.structural_anomalies.overlay.present) {
        std::ostringstream det;
        det << "Size=" << report.structural_anomalies.overlay.size
            << " Entropy=" << std::fixed << std::setprecision(2) << report.structural_anomalies.overlay.entropy;
        out << "Overlay,TrailingData,0x" << std::hex << report.structural_anomalies.overlay.offset << std::dec << "," << escape_csv(det.str()) << "\n";
    }

    for (const auto& cb : report.structural_anomalies.tls_callbacks) {
        out << "TLS_Callback,Callback,0x" << std::hex << cb.rva << std::dec << "," << escape_csv("VA=" + std::to_string(cb.va)) << "\n";
    }

    for (const auto& api : report.iat.suspicious_apis) {
        out << "Flagged_API," << escape_csv(api.name) << "," << escape_csv(api.module_name) << ","
            << escape_csv(analyzers::IatAnalyzer::category_to_string(api.category) + ": " + api.threat_summary) << "\n";
    }

    for (const auto& sc : report.syscalls) {
        out << "Syscall_Or_Assembly," << escape_csv(analyzers::SyscallAnalyzer::type_to_string(sc.type)) << ",0x" << std::hex << sc.rva << std::dec << ","
            << escape_csv("SSN=" + std::to_string(sc.ssn) + " Section=" + sc.section_name) << "\n";
    }

    for (const auto& art : report.strings.artifacts) {
        out << "Artifact," << escape_csv(analyzers::StringsAnalyzer::category_to_string(art.category))
            << ",0x" << std::hex << art.offset << std::dec << "," << escape_csv(art.value) << "\n";
    }

    for (const auto& item : report.deobfuscated.findings) {
        out << "Deobfuscated," << escape_csv(analyzers::Deobfuscator::type_to_string(item.type))
            << ",0x" << std::hex << item.offset << std::dec << "," << escape_csv(item.decoded_value) << "\n";
    }

    out << "Risk_Summary," << escape_csv(scoring::RiskEngine::level_to_string(report.risk.level))
        << "," << report.risk.total_score << "," << escape_csv("Normalized 0-100 Score") << "\n";
}

} // namespace xray::output