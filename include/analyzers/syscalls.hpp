#pragma once
#include "pe/parser.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace xray::analyzers {

enum class SyscallType {
    Direct,
    Indirect
};

struct SyscallStub {
    SyscallType type;
    uint32_t ssn;
    uint32_t rva;
    uint32_t file_offset;
    std::string section_name;
};

class SyscallAnalyzer {
public:
    static std::vector<SyscallStub> analyze(const pe::PeParser& parser);
    static std::string type_to_string(SyscallType type);
};

}