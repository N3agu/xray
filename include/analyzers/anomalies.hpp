#pragma once
#include "pe/parser.hpp"
#include <cstdint>
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

struct StructuralAnomaliesResult {
    std::vector<TlsCallbackInfo> tls_callbacks;
    OverlayInfo overlay;
};

class AnomaliesAnalyzer {
public:
    static StructuralAnomaliesResult analyze(const pe::PeParser& parser);

private:
    static void analyze_tls(const pe::PeParser& parser, StructuralAnomaliesResult& result);
    static void analyze_overlay(const pe::PeParser& parser, StructuralAnomaliesResult& result);
};

}