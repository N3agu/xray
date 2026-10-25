#pragma once
#include "pe/parser.hpp"
#include <string>
#include <vector>

namespace xray::analyzers {

enum class StringCategory {
    Url,
    IpAddress,
    RegistryKey,
    FilePath,
    SuspiciousCommand,
    NamedPipe,
    CryptoWallet
};

struct ExtractedArtifact {
    StringCategory category;
    std::string value;
    uint32_t offset;
};

struct StringsAnalysisResult {
    size_t total_strings_found = 0;
    std::vector<ExtractedArtifact> artifacts;
};

class StringsAnalyzer {
public:
    static StringsAnalysisResult analyze(const pe::PeParser& parser);
    static std::string category_to_string(StringCategory cat);

private:
    static void scan_ascii(std::span<const uint8_t> buffer, StringsAnalysisResult& result);
    static void scan_utf16(std::span<const uint8_t> buffer, StringsAnalysisResult& result);
    static void classify_string(const std::string& str, uint32_t offset, StringsAnalysisResult& result);
};

}