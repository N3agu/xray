#include "analyzers/entropy.hpp"
#include <array>
#include <cmath>

namespace xray::analyzers {

double SectionAnalyzer::calculate_entropy(std::span<const uint8_t> data) noexcept {
    if (data.empty()) {
        return 0.0;
    }

    std::array<size_t, 256> frequencies{};
    for (uint8_t byte : data) {
        ++frequencies[byte];
    }

    double entropy = 0.0;
    double total = static_cast<double>(data.size());

    for (size_t count : frequencies) {
        if (count > 0) {
            double p = static_cast<double>(count) / total;
            entropy -= p * std::log2(p);
        }
    }

    return entropy;
}

std::vector<SectionAnalysis> SectionAnalyzer::analyze(const pe::PeParser& parser) {
    std::vector<SectionAnalysis> results;
    results.reserve(parser.sections().size());

    for (const auto& sec : parser.sections()) {
        SectionAnalysis analysis{
            .name = sec.name,
            .entropy = calculate_entropy(sec.data),
            .is_packed = false,
            .is_rwx = false,
            .is_zero_raw = false,
            .anomalies = {}
        };

        if (analysis.entropy > 7.2) {
            analysis.is_packed = true;
            analysis.anomalies.push_back(SectionAnomaly{
                .section_name = sec.name,
                .description = "High entropy (likely packed, encrypted, or compressed)",
                .is_critical = false
            });
        }

        bool writable = (sec.characteristics & pe::SCN_MEM_WRITE) != 0;
        bool executable = (sec.characteristics & pe::SCN_MEM_EXECUTE) != 0;
        if (writable && executable) {
            analysis.is_rwx = true;
            analysis.anomalies.push_back(SectionAnomaly{
                .section_name = sec.name,
                .description = "W^X violation (section is both Writable and Executable)",
                .is_critical = true
            });
        }

        if (sec.virtual_size > 0 && sec.raw_size == 0) {
            analysis.is_zero_raw = true;
            analysis.anomalies.push_back(SectionAnomaly{
                .section_name = sec.name,
                .description = "Virtual allocation without raw data on disk (unpacked at runtime)",
                .is_critical = true
            });
        }

        if (sec.raw_size > 0 && sec.virtual_size > (sec.raw_size * 5)) {
            analysis.anomalies.push_back(SectionAnomaly{
                .section_name = sec.name,
                .description = "Virtual size significantly exceeds raw disk size",
                .is_critical = false
            });
        }

        results.push_back(std::move(analysis));
    }

    return results;
}

}