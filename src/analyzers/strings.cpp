#include "analyzers/strings.hpp"
#include <cctype>
#include <regex>

namespace xray::analyzers {

std::string StringsAnalyzer::category_to_string(StringCategory cat) {
    switch (cat) {
        case StringCategory::Url:               return "URL";
        case StringCategory::IpAddress:         return "IPv4 Address";
        case StringCategory::RegistryKey:       return "Registry Key";
        case StringCategory::FilePath:          return "File/Directory Path";
        case StringCategory::SuspiciousCommand: return "Suspicious Command";
    }
    return "Unknown";
}

void StringsAnalyzer::classify_string(const std::string& str, uint32_t offset, StringsAnalysisResult& result) {
    static const std::regex url_regex(
        R"((https?|ftp)://[a-zA-Z0-9\-\._~:/\?#\[\]@!$&'\(\)\*\+,;=]+)",
        std::regex::optimize
    );
    // Standard dotted-decimal IPv4 representation
    static const std::regex ip_regex(
        R"(\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b)",
        std::regex::optimize
    );
    static const std::regex reg_regex(
        R"(\b(HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS)\\[a-zA-Z0-9_\\]+)",
        std::regex::optimize | std::regex::icase
    );
    static const std::regex path_regex(
        R"([a-zA-Z]:\\(?:[^<>:"/\\|?*\r\n]+\\)*[^<>:"/\\|?*\r\n]+)",
        std::regex::optimize
    );
    static const std::regex cmd_regex(
        R"(\b(powershell(?:\.exe)?|cmd(?:\.exe)?|wscript(?:\.exe)?|cscript(?:\.exe)?|certutil(?:\.exe)?|bitsadmin(?:\.exe)?|vssadmin(?:\.exe)?|schtasks(?:\.exe)?|regsvr32(?:\.exe)?)\b)",
        std::regex::optimize | std::regex::icase
    );

    std::smatch match;
    if (std::regex_search(str, match, url_regex)) {
        result.artifacts.push_back({StringCategory::Url, match.str(), offset});
        return;
    }
    if (std::regex_search(str, match, ip_regex)) {
        if (match.str() != "0.0.0.0" && match.str() != "127.0.0.1") {
            result.artifacts.push_back({StringCategory::IpAddress, match.str(), offset});
            return;
        }
    }
    if (std::regex_search(str, match, reg_regex)) {
        result.artifacts.push_back({StringCategory::RegistryKey, match.str(), offset});
        return;
    }
    if (std::regex_search(str, match, cmd_regex)) {
        result.artifacts.push_back({StringCategory::SuspiciousCommand, match.str(), offset});
        return;
    }
    if (std::regex_search(str, match, path_regex)) {
        result.artifacts.push_back({StringCategory::FilePath, match.str(), offset});
        return;
    }
}

void StringsAnalyzer::scan_ascii(std::span<const uint8_t> buffer, StringsAnalysisResult& result) {
    std::string current;
    uint32_t start_offset = 0;

    for (size_t i = 0; i < buffer.size(); ++i) {
        uint8_t b = buffer[i];
        if (b >= 0x20 && b <= 0x7E) {
            if (current.empty()) {
                start_offset = static_cast<uint32_t>(i);
            }
            current.push_back(static_cast<char>(b));
        } else {
            if (current.length() >= 5) {
                ++result.total_strings_found;
                classify_string(current, start_offset, result);
            }
            current.clear();
        }
    }

    if (current.length() >= 5) {
        ++result.total_strings_found;
        classify_string(current, start_offset, result);
    }
}

void StringsAnalyzer::scan_utf16(std::span<const uint8_t> buffer, StringsAnalysisResult& result) {
    if (buffer.size() < 2) return;

    std::string current;
    uint32_t start_offset = 0;

    for (size_t i = 0; i + 1 < buffer.size(); i += 2) {
        uint8_t low = buffer[i];
        uint8_t high = buffer[i + 1];

        if (high == 0x00 && low >= 0x20 && low <= 0x7E) {
            if (current.empty()) {
                start_offset = static_cast<uint32_t>(i);
            }
            current.push_back(static_cast<char>(low));
        } else {
            if (current.length() >= 5) {
                ++result.total_strings_found;
                classify_string(current, start_offset, result);
            }
            current.clear();
        }
    }

    if (current.length() >= 5) {
        ++result.total_strings_found;
        classify_string(current, start_offset, result);
    }
}

StringsAnalysisResult StringsAnalyzer::analyze(const pe::PeParser& parser) {
    StringsAnalysisResult result;
    auto buffer = parser.raw_buffer();
    scan_ascii(buffer, result);
    scan_utf16(buffer, result);
    return result;
}

}