#pragma once
#include "pe/parser.hpp"
#include "analyzers/entropy.hpp"
#include "analyzers/iat.hpp"
#include "analyzers/syscalls.hpp"
#include "analyzers/strings.hpp"
#include "analyzers/deobfuscator.hpp"
#include "analyzers/anomalies.hpp"
#include "scoring/engine.hpp"
#include <filesystem>
#include <string>
#include <vector>

namespace xray::core {

enum class OutputFormat {
    Text,
    Json,
    Csv
};

struct ScanOptions {
    bool silent = false;
    OutputFormat format = OutputFormat::Text;
    std::filesystem::path output_file;
    std::filesystem::path target_path;

    bool run_sections = true;
    bool run_iat = true;
    bool run_syscalls = true;
    bool run_strings = true;
    bool run_deobf = true;
    bool run_anomalies = true;

    void disable_all_scans() noexcept {
        run_sections = false;
        run_iat = false;
        run_syscalls = false;
        run_strings = false;
        run_deobf = false;
        run_anomalies = false;
    }
};

struct TriageReport {
    std::string filename;
    size_t file_size = 0;
    bool is_64bit = false;
    uint64_t image_base = 0;
    uint32_t entry_point_rva = 0;

    std::vector<pe::SectionInfo> raw_sections;
    std::vector<analyzers::SectionAnalysis> sections;
    analyzers::IatAnalysisResult iat;
    std::vector<analyzers::SyscallStub> syscalls;
    analyzers::StringsAnalysisResult strings;
    analyzers::DeobfuscationResult deobfuscated;
    analyzers::StructuralAnomaliesResult structural_anomalies;
    scoring::RiskReport risk;
};

}