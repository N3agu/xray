#include "analyzers/anomalies.hpp"
#include "analyzers/entropy.hpp"
#include <algorithm>
#include <unordered_set>

namespace xray::analyzers {

void AnomaliesAnalyzer::analyze_tls(const pe::PeParser& parser, StructuralAnomaliesResult& result) {
    const auto& tls_dir = parser.tls_directory();
    if (tls_dir.virtual_address == 0 || tls_dir.size == 0) {
        return;
    }

    auto tls_offset_opt = parser.rva_to_offset(tls_dir.virtual_address);
    if (!tls_offset_opt) {
        return;
    }

    uint64_t image_base = parser.image_base();
    uint64_t callbacks_va = 0;

    if (parser.is_64bit()) {
        const auto* tls64 = parser.read_struct<pe::ImageTlsDirectory64>(*tls_offset_opt);
        if (!tls64 || tls64->address_of_callbacks == 0) return;
        callbacks_va = tls64->address_of_callbacks;
    } else {
        const auto* tls32 = parser.read_struct<pe::ImageTlsDirectory32>(*tls_offset_opt);
        if (!tls32 || tls32->address_of_callbacks == 0) return;
        callbacks_va = tls32->address_of_callbacks;
    }

    if (callbacks_va <= image_base) {
        return;
    }

    uint64_t callbacks_rva64 = callbacks_va - image_base;
    if (callbacks_rva64 > 0xFFFFFFFFULL) {
        return;
    }

    auto cb_offset_opt = parser.rva_to_offset(static_cast<uint32_t>(callbacks_rva64));
    if (!cb_offset_opt) {
        return;
    }

    uint32_t current_offset = *cb_offset_opt;
    
    // Cap maximum TLS callbacks at 64
    for (size_t i = 0; i < 64; ++i) {
        uint64_t func_va = 0;
        if (parser.is_64bit()) {
            const auto* ptr64 = parser.read_struct<uint64_t>(current_offset);
            if (!ptr64 || *ptr64 == 0) break;
            func_va = *ptr64;
            current_offset += sizeof(uint64_t);
        } else {
            const auto* ptr32 = parser.read_struct<uint32_t>(current_offset);
            if (!ptr32 || *ptr32 == 0) break;
            func_va = *ptr32;
            current_offset += sizeof(uint32_t);
        }

        uint32_t func_rva = (func_va > image_base) ? static_cast<uint32_t>(func_va - image_base) : 0;
        auto func_off_opt = parser.rva_to_offset(func_rva);

        result.tls_callbacks.push_back(TlsCallbackInfo{
            .va = func_va,
            .rva = func_rva,
            .file_offset = func_off_opt.value_or(0)
        });
    }
}

void AnomaliesAnalyzer::analyze_overlay(const pe::PeParser& parser, StructuralAnomaliesResult& result) {
    uint32_t max_raw_end = 0;
    for (const auto& sec : parser.sections()) {
        if (sec.raw_size > 0) {
            uint32_t end = sec.raw_offset + sec.raw_size;
            if (end > max_raw_end) {
                max_raw_end = end;
            }
        }
    }

    auto buffer = parser.raw_buffer();
    if (max_raw_end > 0 && max_raw_end < buffer.size()) {
        size_t overlay_size = buffer.size() - max_raw_end;
        auto overlay_span = buffer.subspan(max_raw_end, overlay_size);

        result.overlay.present = true;
        result.overlay.offset = max_raw_end;
        result.overlay.size = overlay_size;
        result.overlay.entropy = SectionAnalyzer::calculate_entropy(overlay_span);
    }
}

void AnomaliesAnalyzer::analyze_exports(const pe::PeParser& parser, StructuralAnomaliesResult& result) {
    const auto& exp_dir = parser.export_directory();
    if (exp_dir.virtual_address == 0 || exp_dir.size == 0) {
        return;
    }

    auto exp_offset_opt = parser.rva_to_offset(exp_dir.virtual_address);
    if (!exp_offset_opt) {
        return;
    }

    const auto* exp = parser.read_struct<pe::ImageExportDirectory>(*exp_offset_opt);
    if (!exp) {
        return;
    }

    if (auto name_off = parser.rva_to_offset(exp->name)) {
        if (const char* s = parser.read_string(*name_off)) {
            result.exports.dll_name = s;
        }
    }

    auto names_rva_off = parser.rva_to_offset(exp->address_of_names);
    if (!names_rva_off) {
        return;
    }

    uint32_t count = std::min<uint32_t>(exp->number_of_names, 4096);
    for (uint32_t i = 0; i < count; ++i) {
        const auto* func_name_rva = parser.read_struct<uint32_t>(*names_rva_off + i * sizeof(uint32_t));
        if (!func_name_rva) break;

        if (auto fn_off = parser.rva_to_offset(*func_name_rva)) {
            if (const char* fn_str = parser.read_string(*fn_off)) {
                std::string fn(fn_str);
                if (fn.find("ReflectiveLoader") != std::string::npos ||
                    fn.find("StartW") != std::string::npos ||
                    fn.find("ServiceMain") != std::string::npos ||
                    fn.find(" VoidFunc") != std::string::npos) {
                    result.exports.suspicious_exports.push_back(fn);
                }
                result.exports.exported_functions.push_back(std::move(fn));
            }
        }
    }
}

void AnomaliesAnalyzer::analyze_entrypoint_and_sections(const pe::PeParser& parser, StructuralAnomaliesResult& result) {
    static const std::unordered_set<std::string> standard_sections = {
        ".text", "CODE", ".rdata", ".data", ".bss", ".pdata", ".rsrc",
        ".reloc", ".idata", ".edata", ".tls", ".CRT", ".gfids", ".00cfg"
    };

    uint32_t ep = parser.entry_point_rva();
    const auto& secs = parser.sections();

    for (size_t i = 0; i < secs.size(); ++i) {
        const auto& sec = secs[i];
        if (standard_sections.find(sec.name) == standard_sections.end()) {
            result.non_standard_sections.push_back(sec.name);
        }

        uint32_t sec_end = sec.virtual_address + std::max(sec.virtual_size, sec.raw_size);
        if (ep > 0 && ep >= sec.virtual_address && ep < sec_end) {
            result.ep_section_name = sec.name;
            if (sec.name != ".text" && sec.name != "CODE") {
                result.ep_outside_text = true;
            }
            if (secs.size() > 1 && i == secs.size() - 1) {
                result.ep_in_last_section = true;
            }
        }
    }
}

void AnomaliesAnalyzer::analyze_headers_and_mitigations(const pe::PeParser& parser, StructuralAnomaliesResult& result) {
    const auto& sec_dir = parser.security_directory();
    result.is_signed = (sec_dir.virtual_address != 0 && sec_dir.size != 0);

    uint16_t chars = parser.dll_characteristics();
    result.aslr_enabled = (chars & pe::DLL_CHAR_DYNAMIC_BASE) != 0;
    result.dep_enabled  = (chars & pe::DLL_CHAR_NX_COMPAT) != 0;
    result.cfg_enabled  = (chars & pe::DLL_CHAR_GUARD_CF) != 0;

    uint32_t ts = parser.timestamp();
    // 0x2A425E19 is the classic Delphi compiler constant timestamp (June 19, 1992)
    if (ts == 0) {
        result.timestamp_anomaly = true;
        result.timestamp_note = "Zeroed timestamp (0x00000000)";
    } else if (ts == 0x2A425E19) {
        result.timestamp_anomaly = true;
        result.timestamp_note = "Delphi static timestamp (1992-06-19)";
    } else if (ts < 946684800) {
        // Prior to 2000-01-01 (946684800 Unix epoch)
        result.timestamp_anomaly = true;
        result.timestamp_note = "Pre-2000 compile timestamp (likely forged)";
    } else if (ts > 1800000000 && ts != 0xFFFFFFFF) {
        // Future timestamp beyond ~2027 (excluding Windows Reproducible Build hashes near 0xFFFFFFFF)
        result.timestamp_anomaly = true;
        result.timestamp_note = "Future compile timestamp or reproducible build hash";
    }
}

StructuralAnomaliesResult AnomaliesAnalyzer::analyze(const pe::PeParser& parser) {
    StructuralAnomaliesResult result;
    analyze_tls(parser, result);
    analyze_overlay(parser, result);
    analyze_exports(parser, result);
    analyze_entrypoint_and_sections(parser, result);
    analyze_headers_and_mitigations(parser, result);
    return result;
}

}