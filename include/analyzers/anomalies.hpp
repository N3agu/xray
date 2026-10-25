#pragma once
#include "pe/parser.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace xray::analyzers {

struct TlsCallbackInfo {
    uint64_t va;
    uint32_t rva;
    uint32_t file_offset;
};

struct OverlayInfo {
    bool present = false;
    uint32_t offset = 0;
    size_t size = 0;
    double entropy = 0.0;
};

struct ExportInfo {
    std::string dll_name;
    std::vector<std::string> exported_functions;
    std::vector<std::string> suspicious_exports;
};

struct StructuralAnomaliesResult {
    std::vector<TlsCallbackInfo> tls_callbacks;
    OverlayInfo overlay;
    ExportInfo exports;

    bool ep_outside_text = false;
    bool ep_in_last_section = false;
    std::string ep_section_name;
    std::vector<std::string> non_standard_sections;

    bool is_signed = false;
    bool aslr_enabled = false;
    bool dep_enabled = false;
    bool cfg_enabled = false;
    bool timestamp_anomaly = false;
    std::string timestamp_note;
};

class AnomaliesAnalyzer {
public:
    static StructuralAnomaliesResult analyze(const pe::PeParser& parser);

private:
    static void analyze_tls(const pe::PeParser& parser, StructuralAnomaliesResult& result);
    static void analyze_overlay(const pe::PeParser& parser, StructuralAnomaliesResult& result);
    static void analyze_exports(const pe::PeParser& parser, StructuralAnomaliesResult& result);
    static void analyze_entrypoint_and_sections(const pe::PeParser& parser, StructuralAnomaliesResult& result);
    static void analyze_headers_and_mitigations(const pe::PeParser& parser, StructuralAnomaliesResult& result);
};

}