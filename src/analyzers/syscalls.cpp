#include "analyzers/syscalls.hpp"

namespace xray::analyzers {

std::string SyscallAnalyzer::type_to_string(SyscallType type) {
    switch (type) {
        case SyscallType::Direct:   return "Direct Syscall";
        case SyscallType::Indirect: return "Indirect Syscall";
    }
    return "Unknown";
}

std::vector<SyscallStub> SyscallAnalyzer::analyze(const pe::PeParser& parser) {
    std::vector<SyscallStub> findings;

    if (!parser.is_64bit()) {
        return findings;
    }

    for (const auto& sec : parser.sections()) {
        if ((sec.characteristics & pe::SCN_MEM_EXECUTE) == 0 || sec.data.empty()) {
            continue;
        }

        const auto data = sec.data;
        if (data.size() < 8) {
            continue;
        }

        for (size_t i = 0; i + 7 < data.size(); ++i) {
            // mov r10, rcx (4C 8B D1) followed by mov eax, imm32 (B8)
            if (data[i] == 0x4C && data[i + 1] == 0x8B && data[i + 2] == 0xD1 && data[i + 3] == 0xB8) {
                uint32_t ssn = static_cast<uint32_t>(data[i + 4]) |
                              (static_cast<uint32_t>(data[i + 5]) << 8) |
                              (static_cast<uint32_t>(data[i + 6]) << 16) |
                              (static_cast<uint32_t>(data[i + 7]) << 24);

                size_t lookahead_limit = (i + 24 < data.size()) ? i + 24 : data.size();
                for (size_t j = i + 8; j + 1 < lookahead_limit; ++j) {
                    // Direct syscall: 0F 05 (syscall)
                    if (data[j] == 0x0F && data[j + 1] == 0x05) {
                        findings.push_back(SyscallStub{
                            .type = SyscallType::Direct,
                            .ssn = ssn,
                            .rva = static_cast<uint32_t>(sec.virtual_address + i),
                            .file_offset = static_cast<uint32_t>(sec.raw_offset + i),
                            .section_name = sec.name
                        });
                        break;
                    }

                    // Indirect jump: jmp [rip+offset] (FF 25)
                    if (data[j] == 0xFF && data[j + 1] == 0x25) {
                        findings.push_back(SyscallStub{
                            .type = SyscallType::Indirect,
                            .ssn = ssn,
                            .rva = static_cast<uint32_t>(sec.virtual_address + i),
                            .file_offset = static_cast<uint32_t>(sec.raw_offset + i),
                            .section_name = sec.name
                        });
                        break;
                    }

                    // Indirect register jump: FF E0 through FF E7 (jmp rax ... jmp rdi)
                    // 0xE0 to 0xE7 are the modr/m encodings for register-indirect jumps
                    if (data[j] == 0xFF && data[j + 1] >= 0xE0 && data[j + 1] <= 0xE7) {
                        findings.push_back(SyscallStub{
                            .type = SyscallType::Indirect,
                            .ssn = ssn,
                            .rva = static_cast<uint32_t>(sec.virtual_address + i),
                            .file_offset = static_cast<uint32_t>(sec.raw_offset + i),
                            .section_name = sec.name
                        });
                        break;
                    }
                }
            }
        }
    }

    return findings;
}

}