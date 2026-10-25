#pragma once
#include "core/report.hpp"
#include <ostream>
#include <string>
#include <string_view>

namespace xray::output {

class Reporter {
public:
    static void render(
        const core::TriageReport& report,
        const core::ScanOptions& options,
        std::ostream& out,
        std::string_view banner
    );

private:
    static void render_text(const core::TriageReport& report, const core::ScanOptions& options, std::ostream& out, std::string_view banner);
    static void render_json(const core::TriageReport& report, const core::ScanOptions& options, std::ostream& out);
    static void render_csv(const core::TriageReport& report, const core::ScanOptions& options, std::ostream& out);

    static std::string format_permissions(uint32_t chars);
    static std::string escape_json(std::string_view s);
    static std::string escape_csv(std::string_view s);
};

}