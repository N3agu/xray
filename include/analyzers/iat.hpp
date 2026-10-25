#pragma once
#include "pe/parser.hpp"
#include <string>
#include <unordered_map>
#include <vector>

namespace xray::analyzers {

enum class ApiCategory {
    ProcessInjection,
    DefenseEvasion,
    DynamicLoading,
    MemoryManipulation,
    ProcessCreation,
    SystemDiscovery,
    NetworkC2,
    Cryptography,
    SpywareKeylogging
};

struct SuspiciousApi {
    std::string name;
    std::string module_name;
    ApiCategory category;
    std::string threat_summary;
};

struct ImportedLibrary {
    std::string name;
    std::vector<std::string> functions;
};

struct IatAnalysisResult {
    std::vector<ImportedLibrary> libraries;
    std::vector<SuspiciousApi> suspicious_apis;
    size_t total_import_count = 0;
    bool low_import_count_anomaly = false;
};

class IatAnalyzer {
public:
    static IatAnalysisResult analyze(const pe::PeParser& parser);
    static std::string category_to_string(ApiCategory cat);

private:
    static void triage_api(const std::string& module_name, const std::string& func_name, IatAnalysisResult& result);
};

}