#include "analyzers/iat.hpp"
#include <algorithm>

namespace xray::analyzers {

std::string IatAnalyzer::category_to_string(ApiCategory cat) {
    switch (cat) {
        case ApiCategory::ProcessInjection:    return "Process Injection";
        case ApiCategory::DefenseEvasion:       return "Defense Evasion";
        case ApiCategory::DynamicLoading:       return "Dynamic Resolution";
        case ApiCategory::MemoryManipulation:   return "Memory Manipulation";
        case ApiCategory::ProcessCreation:      return "Process Creation";
        case ApiCategory::SystemDiscovery:      return "System Discovery";
    }
    return "Unknown";
}

void IatAnalyzer::triage_api(const std::string& module_name, const std::string& func_name, IatAnalysisResult& result) {
    static const std::unordered_map<std::string, std::pair<ApiCategory, std::string>> known_threats = {
        {"VirtualAllocEx",       {ApiCategory::ProcessInjection, "Remote memory allocation"}},
        {"WriteProcessMemory",   {ApiCategory::ProcessInjection, "Writing to foreign process memory"}},
        {"CreateRemoteThread",   {ApiCategory::ProcessInjection, "Remote thread execution"}},
        {"QueueUserAPC",         {ApiCategory::ProcessInjection, "Asynchronous Procedure Call injection"}},
        {"SetThreadContext",     {ApiCategory::ProcessInjection, "Thread hijacking / context manipulation"}},
        {"NtQueueApcThread",     {ApiCategory::ProcessInjection, "Native APC injection"}},
        {"RtlCreateUserThread",  {ApiCategory::ProcessInjection, "Native thread injection"}},

        {"AmsiScanBuffer",       {ApiCategory::DefenseEvasion, "AMSI inspection hook target"}},
        {"AmsiScanString",       {ApiCategory::DefenseEvasion, "AMSI inspection hook target"}},
        {"EtwEventWrite",        {ApiCategory::DefenseEvasion, "ETW event logging target"}},
        {"MiniDumpWriteDump",    {ApiCategory::DefenseEvasion, "Process memory dumping (LSASS)"}},
        {"AdjustTokenPrivileges",{ApiCategory::DefenseEvasion, "Token privilege escalation"}},

        {"LoadLibraryA",         {ApiCategory::DynamicLoading, "Runtime DLL loading"}},
        {"LoadLibraryW",         {ApiCategory::DynamicLoading, "Runtime DLL loading"}},
        {"LoadLibraryExA",       {ApiCategory::DynamicLoading, "Runtime DLL loading"}},
        {"LoadLibraryExW",       {ApiCategory::DynamicLoading, "Runtime DLL loading"}},
        {"GetProcAddress",       {ApiCategory::DynamicLoading, "Runtime API resolution"}},
        {"LdrLoadDll",           {ApiCategory::DynamicLoading, "Native runtime DLL loading"}},
        {"LdrGetProcedureAddress",{ApiCategory::DynamicLoading, "Native API resolution"}},

        {"VirtualAlloc",         {ApiCategory::MemoryManipulation, "Executable memory allocation"}},
        {"VirtualProtect",       {ApiCategory::MemoryManipulation, "Memory permission modification"}},
        {"VirtualProtectEx",     {ApiCategory::MemoryManipulation, "Remote memory permission modification"}},

        {"CreateProcessA",       {ApiCategory::ProcessCreation, "Spawning subprocess"}},
        {"CreateProcessW",       {ApiCategory::ProcessCreation, "Spawning subprocess"}},
        {"WinExec",              {ApiCategory::ProcessCreation, "Spawning command line"}},
        {"ShellExecuteA",        {ApiCategory::ProcessCreation, "Shell execution"}},
        {"ShellExecuteW",        {ApiCategory::ProcessCreation, "Shell execution"}},

        {"IsDebuggerPresent",    {ApiCategory::SystemDiscovery, "Anti-debugging check"}},
        {"CheckRemoteDebuggerPresent", {ApiCategory::SystemDiscovery, "Anti-debugging check"}}
    };

    auto it = known_threats.find(func_name);
    if (it != known_threats.end()) {
        result.suspicious_apis.push_back(SuspiciousApi{
            .name = func_name,
            .module_name = module_name,
            .category = it->second.first,
            .threat_summary = it->second.second
        });
    }
}

IatAnalysisResult IatAnalyzer::analyze(const pe::PeParser& parser) {
    IatAnalysisResult result;
    const auto& import_dir = parser.import_directory();

    if (import_dir.virtual_address == 0 || import_dir.size == 0) {
        result.low_import_count_anomaly = true;
        return result;
    }

    auto desc_offset_opt = parser.rva_to_offset(import_dir.virtual_address);
    if (!desc_offset_opt) {
        return result;
    }

    uint32_t current_desc_offset = *desc_offset_opt;

    while (true) {
        const auto* descriptor = parser.read_struct<pe::ImageImportDescriptor>(current_desc_offset);
        if (!descriptor || (descriptor->characteristics == 0 && descriptor->first_thunk == 0)) {
            break;
        }

        auto mod_name_offset = parser.rva_to_offset(descriptor->name);
        if (!mod_name_offset) {
            current_desc_offset += sizeof(pe::ImageImportDescriptor);
            continue;
        }

        const char* raw_mod_name = parser.read_string(*mod_name_offset);
        std::string module_name = raw_mod_name ? raw_mod_name : "UNKNOWN.DLL";

        ImportedLibrary lib;
        lib.name = module_name;

        uint32_t thunk_rva = descriptor->original_first_thunk != 0 
                             ? descriptor->original_first_thunk 
                             : descriptor->first_thunk;

        auto thunk_offset_opt = parser.rva_to_offset(thunk_rva);
        if (thunk_offset_opt) {
            uint32_t current_thunk_offset = *thunk_offset_opt;

            while (true) {
                if (parser.is_64bit()) {
                    const auto* thunk64 = parser.read_struct<uint64_t>(current_thunk_offset);
                    if (!thunk64 || *thunk64 == 0) {
                        break;
                    }

                    // Ordinal mask for 64-bit PE (0x8000000000000000)
                    if ((*thunk64 & 0x8000000000000000ULL) == 0) {
                        uint32_t name_rva = static_cast<uint32_t>(*thunk64 & 0xFFFFFFFF);
                        auto name_offset = parser.rva_to_offset(name_rva);
                        if (name_offset) {
                            const auto* ibn = parser.read_struct<pe::ImageImportByName>(*name_offset);
                            if (ibn) {
                                const char* func_name_ptr = parser.read_string(*name_offset + sizeof(uint16_t));
                                if (func_name_ptr) {
                                    std::string func_name(func_name_ptr);
                                    triage_api(module_name, func_name, result);
                                    lib.functions.push_back(std::move(func_name));
                                    ++result.total_import_count;
                                }
                            }
                        }
                    } else {
                        // Import by ordinal
                        uint16_t ordinal = static_cast<uint16_t>(*thunk64 & 0xFFFF);
                        lib.functions.push_back("Ordinal#" + std::to_string(ordinal));
                        ++result.total_import_count;
                    }
                    current_thunk_offset += sizeof(uint64_t);
                } else {
                    const auto* thunk32 = parser.read_struct<uint32_t>(current_thunk_offset);
                    if (!thunk32 || *thunk32 == 0) {
                        break;
                    }

                    // Ordinal mask for 32-bit PE (0x80000000)
                    if ((*thunk32 & 0x80000000) == 0) {
                        auto name_offset = parser.rva_to_offset(*thunk32);
                        if (name_offset) {
                            const auto* ibn = parser.read_struct<pe::ImageImportByName>(*name_offset);
                            if (ibn) {
                                const char* func_name_ptr = parser.read_string(*name_offset + sizeof(uint16_t));
                                if (func_name_ptr) {
                                    std::string func_name(func_name_ptr);
                                    triage_api(module_name, func_name, result);
                                    lib.functions.push_back(std::move(func_name));
                                    ++result.total_import_count;
                                }
                            }
                        }
                    } else {
                        // Import by ordinal
                        uint16_t ordinal = static_cast<uint16_t>(*thunk32 & 0xFFFF);
                        lib.functions.push_back("Ordinal#" + std::to_string(ordinal));
                        ++result.total_import_count;
                    }
                    current_thunk_offset += sizeof(uint32_t);
                }
            }
        }

        result.libraries.push_back(std::move(lib));
        current_desc_offset += sizeof(pe::ImageImportDescriptor);
    }

    if (result.total_import_count < 5) {
        result.low_import_count_anomaly = true;
    }

    return result;
}

}