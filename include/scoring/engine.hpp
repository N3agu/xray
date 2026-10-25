#pragma once
#include "analyzers/entropy.hpp"
#include "analyzers/iat.hpp"
#include "analyzers/syscalls.hpp"
#include "analyzers/strings.hpp"
#include "analyzers/deobfuscator.hpp"
#include "analyzers/anomalies.hpp"
#include <string>
#include <vector>

namespace xray::scoring {

enum class ThreatLevel {
    Clean,
    Suspicious,
    Malicious
};

struct ScoreRule {
    std::string rule_name;
    uint32_t points;
    std::string reason;
};

struct RiskReport {
    uint32_t total_score = 0;
    ThreatLevel level = ThreatLevel::Clean;
    std::vector<ScoreRule> triggered_rules;
};

class RiskEngine {
public:
    static RiskReport evaluate(
        const std::vector<analyzers::SectionAnalysis>& sections,
        const analyzers::IatAnalysisResult& iat,
        const std::vector<analyzers::SyscallStub>& syscalls,
        const analyzers::StringsAnalysisResult& strings,
        const analyzers::DeobfuscationResult& deobf,
        const analyzers::StructuralAnomaliesResult& anomalies
    );

    static std::string level_to_string(ThreatLevel level);
};

}