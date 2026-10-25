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
    const analyzers::DeobfuscationResult& deobf,
    const analyzers::StructuralAnomaliesResult& anomalies
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

    bool has_syscall = false;
    bool has_peb_walk = false;
    for (const auto& sc : syscalls) {
        if (sc.type == analyzers::SyscallType::Direct || sc.type == analyzers::SyscallType::Indirect) {
            has_syscall = true;
        } else {
            has_peb_walk = true;
        }
    }

    // Direct and indirect syscall stubs bypass EDR/AV hooks (weight: 40)
    if (has_syscall) {
        report.triggered_rules.push_back({
            "EVASIVE_SYSCALL_STUBS",
            40,
            "Direct or indirect syscall stubs found outside ntdll.dll"
        });
    }

    // Direct PEB segment access indicates shellcode or manual import resolution (weight: 30)
    if (has_peb_walk) {
        report.triggered_rules.push_back({
            "DIRECT_PEB_WALKING",
            30,
            "Direct PEB segment register access (gs:[60h] / fs:[30h]) detected"
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

    // Entry point outside standard code section (weight: 25)
    if (anomalies.ep_outside_text || anomalies.ep_in_last_section) {
        report.triggered_rules.push_back({
            "ABNORMAL_ENTRYPOINT",
            25,
            "Entry point resides outside .text or inside the final section (" + anomalies.ep_section_name + ")"
        });
    }

    // Reflective loader or suspicious DLL export names (weight: 35)
    if (!anomalies.exports.suspicious_exports.empty()) {
        report.triggered_rules.push_back({
            "SUSPICIOUS_EXPORT_NAME",
            35,
            "Export table contains known loader stub (" + anomalies.exports.suspicious_exports.front() + ")"
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

    // TLS callbacks execute code before main entrypoint (weight: 25)
    if (!anomalies.tls_callbacks.empty()) {
        report.triggered_rules.push_back({
            "TLS_CALLBACKS_PRESENT",
            25,
            "Pre-entrypoint TLS callback routines registered"
        });
    }

    // High-entropy overlay (> 7.2) larger than 512 bytes indicates appended encrypted stage (weight: 20)
    if (anomalies.overlay.present && anomalies.overlay.entropy > 7.2 && anomalies.overlay.size > 512) {
        report.triggered_rules.push_back({
            "HIGH_ENTROPY_OVERLAY",
            20,
            "Encrypted or compressed trailing overlay data appended to binary"
        });
    }

    // Disabled ASLR and DEP together coupled with no digital signature (weight: 15)
    if (!anomalies.aslr_enabled && !anomalies.dep_enabled && !anomalies.is_signed) {
        report.triggered_rules.push_back({
            "DISABLED_MITIGATIONS",
            15,
            "Unsigned binary with both ASLR and DEP/NX disabled"
        });
    }

    // Forged or zeroed PE compile timestamp (weight: 10)
    if (anomalies.timestamp_anomaly) {
        report.triggered_rules.push_back({
            "TIMESTAMP_ANOMALY",
            10,
            anomalies.timestamp_note
        });
    }

    // Process injection API usage (weight: 25)
    bool has_injection = false;
    bool has_evasion = false;
    bool has_spyware = false;
    for (const auto& api : iat.suspicious_apis) {
        if (api.category == analyzers::ApiCategory::ProcessInjection) has_injection = true;
        if (api.category == analyzers::ApiCategory::DefenseEvasion) has_evasion = true;
        if (api.category == analyzers::ApiCategory::SpywareKeylogging) has_spyware = true;
    }

    if (has_injection) {
        report.triggered_rules.push_back({
            "PROCESS_INJECTION_API",
            25,
            "Import table includes process memory manipulation or injection APIs"
        });
    }

    // Defense evasion API usage (weight: 20)
    if (has_evasion) {
        report.triggered_rules.push_back({
            "DEFENSE_EVASION_API",
            20,
            "Import table includes AMSI/ETW or token privilege evasion APIs"
        });
    }

    // Keylogging / Spyware API usage (weight: 15)
    if (has_spyware) {
        report.triggered_rules.push_back({
            "SPYWARE_HOOKING_API",
            15,
            "Import table includes keystroke polling, global hooks, or clipboard harvesting"
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

    // Suspicious shell execution utilities or named pipes in strings (weight: 15)
    bool has_cmd = false;
    bool has_pipe = false;
    for (const auto& art : strings.artifacts) {
        if (art.category == analyzers::StringCategory::SuspiciousCommand) has_cmd = true;
        if (art.category == analyzers::StringCategory::NamedPipe) has_pipe = true;
    }
    if (has_cmd) {
        report.triggered_rules.push_back({
            "SUSPICIOUS_CMD_REFERENCE",
            15,
            "References to system execution utilities (powershell, cmd, vssadmin, etc.)"
        });
    }
    if (has_pipe) {
        report.triggered_rules.push_back({
            "NAMED_PIPE_C2_CHANNEL",
            15,
            "Embedded Named Pipe path detected (commonly used for C2 or privilege escalation)"
        });
    }

    uint32_t raw_score = 0;
    for (const auto& rule : report.triggered_rules) {
        raw_score += rule.points;
    }

    // Cap maximum normalized score at 100
    report.total_score = std::min(raw_score, 100u);

    // Score thresholds: >= 60 Malicious, >= 30 Suspicious, < 30 Clean
    if (report.total_score >= 60) {
        report.level = ThreatLevel::Malicious;
    } else if (report.total_score >= 30) {
        report.level = ThreatLevel::Suspicious;
    } else {
        report.level = ThreatLevel::Clean;
    }

    return report;
}

} // namespace xray::scoring