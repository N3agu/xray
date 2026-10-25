#include "analyzers/syscalls.hpp"

namespace xray::analyzers {

std::string SyscallAnalyzer::type_to_string(SyscallType type) {
    switch (type) {
        case SyscallType::Direct:    return "Direct Syscall";
        case SyscallType::Indirect:  return "Indirect Syscall";
        case SyscallType::PebWalk64: return "PEB Walk (gs:[60h])";
        case SyscallType::PebWalk32: return "PEB Walk (fs:[30h])";
    }
    return "Unknown";
}

std::vector<SyscallStub> SyscallAnalyzer::analyze(const pe::PeParser& parser) {
    std::vector<SyscallStub> findings;

    for (const auto& sec : parser.sections()) {
        if ((sec.characteristics & pe::SCN_MEM_EXECUTE) == 0 || sec.data.empty()) {
            continue;
        }

        const auto data = sec.data;
        if (data.size() < 8) {
            continue;
        }

        for (size_t i = 0; i + 7 < data.size(); ++i) {
            // x64 PEB walk: 65 48 8B XX 25 60 00 00 00 (mov reg, gs:[0x60])
            if (parser.is_64bit() && i + 8 < data.size() &&
                data[i] == 0x65 && data[i + 1] == 0x48 && data[i + 2] == 0x8B &&
                data[i + 4] == 0x25 && data[i + 5] == 0x60 && data[i + 6] == 0x00 &&
                data[i + 7] == 0x00 && data[i + 8] == 0x00) {
                findings.push_back(SyscallStub{
                    .type = SyscallType::PebWalk64,
                    .ssn = 0,
                    .rva = static_cast<uint32_t>(sec.virtual_address + i),
                    .file_offset = static_cast<uint32_t>(sec.raw_offset + i),
                    .section_name = sec.name
                });
            }

            // x86 PEB walk: 64 A1 30 00 00 00 (mov eax, fs:[0x30]) or 64 8B XX 30 00 00 00
            if (!parser.is_64bit()) {
                if (data[i] == 0x64 && data[i + 1] == 0xA1 && data[i + 2] == 0x30 &&
                    data[i + 3] == 0x00 && data[i + 4] == 0x00 && data[i + 5] == 0x00) {
                    findings.push_back(SyscallStub{
                        .type = SyscallType::PebWalk32,
                        .ssn = 0,
                        .rva = static_cast<uint32_t>(sec.virtual_address + i),
                        .file_offset = static_cast<uint32_t>(sec.raw_offset + i),
                        .section_name = sec.name
                    });
                } else if (data[i] == 0x64 && data[i + 1] == 0x8B && data[i + 3] == 0x30 &&
                           data[i + 4] == 0x00 && data[i + 5] == 0x00 && data[i + 6] == 0x00) {
                    findings.push_back(SyscallStub{
                        .type = SyscallType::PebWalk32,
                        .ssn = 0,
                        .rva = static_cast<uint32_t>(sec.virtual_address + i),
                        .file_offset = static_cast<uint32_t>(sec.raw_offset + i),
                        .section_name = sec.name
                    });
                }
            }

            // x64 Direct/Indirect syscall prologue: 4C 8B D1 B8 (mov r10, rcx; mov eax, imm32)
            if (parser.is_64bit() && data[i] == 0x4C && data[i + 1] == 0x8B && data[i + 2] == 0xD1 && data[i + 3] == 0xB8) {
                uint32_t ssn = static_cast<uint32_t>(data[i + 4]) |
                              (static_cast<uint32_t>(data[i + 5]) << 8) |
                              (static_cast<uint32_t>(data[i + 6]) << 16) |
                              (static_cast<uint32_t>(data[i + 7]) << 24);

                // Sanity check SSN (< 0x2000 for Windows NT/Win32k syscalls)
                if (ssn > 0x2000) continue;

                size_t lookahead_limit = (i + 24 < data.size()) ? i + 24 : data.size();
                for (size_t j = i + 8; j + 1 < lookahead_limit; ++j) {
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