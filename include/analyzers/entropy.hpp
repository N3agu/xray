#pragma once
#include "pe/parser.hpp"
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace xray::analyzers {

struct SectionAnomaly {
    std::string section_name;
    std::string description;
    bool is_critical;
};

struct SectionAnalysis {
    std::string name;
    double entropy;
    bool is_packed;
    bool is_rwx;
    bool is_zero_raw;
    std::vector<SectionAnomaly> anomalies;
};

class SectionAnalyzer {
public:
    static double calculate_entropy(std::span<const uint8_t> data) noexcept;
    static std::vector<SectionAnalysis> analyze(const pe::PeParser& parser);
};

}