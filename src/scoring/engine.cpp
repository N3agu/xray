#include "scoring/engine.hpp"
#include <algorithm>

namespace xray::scoring {

std::string RiskEngine::level_to_string(ThreatLevel level) {
    switch (level) {
        case ThreatLevel::Clean:      return "CLEAN";
        case ThreatLevel::Suspicious: return "SUSPICIOUS";
        case ThreatLevel::Malicious:  return "MALICIOUS";
    }
    return "UNKNOWN";
}

RiskReport RiskEngine::evaluate(
    const std::vector<analyzers::SectionAnalysis>& sections,
    const analyzers::IatAnalysisResult& iat,
    const std::vector<analyzers::SyscallStub>& syscalls,
    const analyzers::StringsAnalysisResult& strings,
    const analyzers::DeobfuscationResult& deobf
) {
    RiskReport report;

    bool has_high_entropy = false;
    bool has_rwx = false;
    bool has_zero_raw = false;

    for (const auto& sec : sections) {
        if (sec.is_packed) has_high_entropy = true;
        if (sec.is_rwx) has_rwx = true;
        if (sec.is_zero_raw) has_zero_raw = true;
    }

    // Direct and indirect syscall stubs bypass EDR/AV hooks (weight: 40)
    if (!syscalls.empty()) {
        report.triggered_rules.push_back({
            "EVASIVE_SYSCALL_STUBS",
            40,
            "Direct or indirect syscall stubs found outside ntdll.dll"
        });
    }

    // Memory permission violation (W^X) allowing arbitrary in-place execution (weight: 35)
    if (has_rwx) {
        report.triggered_rules.push_back({
            "RWX_PERMISSIONS",
            35,
            "Writable and executable section detected (W^X violation)"
        });
    }

    // Unmapped raw section allocated in memory at load time (weight: 25)
    if (has_zero_raw) {
        report.triggered_rules.push_back({
            "ZERO_RAW_SECTION",
            25,
            "Section with zero raw size on disk but allocated virtual memory"
        });
    }

    // Correlation: High entropy combined with low import count indicates packed loader (weight: 35)
    if (has_high_entropy && iat.low_import_count_anomaly) {
        report.triggered_rules.push_back({
            "PACKED_IMPORT_ANOMALY",
            35,
            "High section entropy combined with abnormally low import count"
        });
    } else if (has_high_entropy) {
        // High entropy isolated (weight: 15)
        report.triggered_rules.push_back({
            "HIGH_ENTROPY",
            15,
            "Packed or encrypted section detected"
        });
    } else if (iat.low_import_count_anomaly) {
        // Low import count isolated (weight: 10)
        report.triggered_rules.push_back({
            "LOW_IMPORT_COUNT",
            10,
            "Import count < 5 indicates manual API resolution or minimal stub"
        });
    }

    // Process injection API usage (weight: 25)
    bool has_injection = false;
    for (const auto& api : iat.suspicious_apis) {
        if (api.category == analyzers::ApiCategory::ProcessInjection) {
            has_injection = true;
            break;
        }
    }
    if (has_injection) {
        report.triggered_rules.push_back({
            "PROCESS_INJECTION_API",
            25,
            "Import table includes process memory manipulation or injection APIs"
        });
    }

    // Defense evasion API usage (weight: 20)
    bool has_evasion = false;
    for (const auto& api : iat.suspicious_apis) {
        if (api.category == analyzers::ApiCategory::DefenseEvasion) {
            has_evasion = true;
            break;
        }
    }
    if (has_evasion) {
        report.triggered_rules.push_back({
            "DEFENSE_EVASION_API",
            20,
            "Import table includes AMSI/ETW or token privilege evasion APIs"
        });
    }

    // Deobfuscated strings extracted via XOR or Base64 (weight: 25)
    if (!deobf.findings.empty()) {
        report.triggered_rules.push_back({
            "OBFUSCATED_STRINGS_RECOVERED",
            25,
            "Obfuscated strings successfully decrypted via XOR cribbing or Base64"
        });
    }

    // Suspicious shell execution utilities in strings (weight: 15)
    bool has_cmd = false;
    for (const auto& art : strings.artifacts) {
        if (art.category == analyzers::StringCategory::SuspiciousCommand) {
            has_cmd = true;
            break;
        }
    }
    if (has_cmd) {
        report.triggered_rules.push_back({
            "SUSPICIOUS_CMD_REFERENCE",
            15,
            "References to system execution utilities (powershell, cmd, vssadmin, etc.)"
        });
    }

    uint32_t raw_score = 0;
    for (const auto& rule : report.triggered_rules) {
        raw_score += rule.points;
    }

    report.total_score = std::min(raw_score, 100u);

    if (report.total_score >= 60) {
        report.level = ThreatLevel::Malicious;
    } else if (report.total_score >= 30) {
        report.level = ThreatLevel::Suspicious;
    } else {
        report.level = ThreatLevel::Clean;
    }

    return report;
}

}