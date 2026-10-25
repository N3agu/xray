#include "analyzers/anomalies.hpp"
#include "analyzers/entropy.hpp"
#include <algorithm>

namespace xray::analyzers {

void AnomaliesAnalyzer::analyze_tls(const pe::PeParser& parser, StructuralAnomaliesResult& result) {
    const auto& tls_dir = parser.tls_directory();
    if (tls_dir.virtual_address == 0 || tls_dir.size == 0) {
        return;
    }

    auto tls_offset_opt = parser.rva_to_offset(tls_dir.virtual_address);
    if (!tls_offset_opt) {
        return;
    }

    uint64_t image_base = parser.image_base();
    uint64_t callbacks_va = 0;

    if (parser.is_64bit()) {
        const auto* tls64 = parser.read_struct<pe::ImageTlsDirectory64>(*tls_offset_opt);
        if (!tls64 || tls64->address_of_callbacks == 0) return;
        callbacks_va = tls64->address_of_callbacks;
    } else {
        const auto* tls32 = parser.read_struct<pe::ImageTlsDirectory32>(*tls_offset_opt);
        if (!tls32 || tls32->address_of_callbacks == 0) return;
        callbacks_va = tls32->address_of_callbacks;
    }

    if (callbacks_va <= image_base) {
        return;
    }

    uint64_t callbacks_rva64 = callbacks_va - image_base;
    if (callbacks_rva64 > 0xFFFFFFFFULL) {
        return;
    }

    auto cb_offset_opt = parser.rva_to_offset(static_cast<uint32_t>(callbacks_rva64));
    if (!cb_offset_opt) {
        return;
    }

    uint32_t current_offset = *cb_offset_opt;
    for (size_t i = 0; i < 64; ++i) {
        uint64_t func_va = 0;
        if (parser.is_64bit()) {
            const auto* ptr64 = parser.read_struct<uint64_t>(current_offset);
            if (!ptr64 || *ptr64 == 0) break;
            func_va = *ptr64;
            current_offset += sizeof(uint64_t);
        } else {
            const auto* ptr32 = parser.read_struct<uint32_t>(current_offset);
            if (!ptr32 || *ptr32 == 0) break;
            func_va = *ptr32;
            current_offset += sizeof(uint32_t);
        }

        uint32_t func_rva = (func_va > image_base) ? static_cast<uint32_t>(func_va - image_base) : 0;
        auto func_off_opt = parser.rva_to_offset(func_rva);

        result.tls_callbacks.push_back(TlsCallbackInfo{
            .va = func_va,
            .rva = func_rva,
            .file_offset = func_off_opt.value_or(0)
        });
    }
}

void AnomaliesAnalyzer::analyze_overlay(const pe::PeParser& parser, StructuralAnomaliesResult& result) {
    uint32_t max_raw_end = 0;
    for (const auto& sec : parser.sections()) {
        if (sec.raw_size > 0) {
            uint32_t end = sec.raw_offset + sec.raw_size;
            if (end > max_raw_end) {
                max_raw_end = end;
            }
        }
    }

    auto buffer = parser.raw_buffer();
    if (max_raw_end > 0 && max_raw_end < buffer.size()) {
        size_t overlay_size = buffer.size() - max_raw_end;
        auto overlay_span = buffer.subspan(max_raw_end, overlay_size);

        result.overlay.present = true;
        result.overlay.offset = max_raw_end;
        result.overlay.size = overlay_size;
        result.overlay.entropy = SectionAnalyzer::calculate_entropy(overlay_span);
    }
}

StructuralAnomaliesResult AnomaliesAnalyzer::analyze(const pe::PeParser& parser) {
    StructuralAnomaliesResult result;
    analyze_tls(parser, result);
    analyze_overlay(parser, result);
    return result;
}

}