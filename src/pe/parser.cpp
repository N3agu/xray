#include "pe/parser.hpp"
#include <algorithm>
#include <cstring>

namespace xray::pe {

PeParser::PeParser(std::span<const uint8_t> buffer) : buffer_(buffer) {
    valid_ = parse();
}

bool PeParser::parse() {
    const auto* dos = read_struct<DosHeader>(0);
    if (!dos || dos->e_magic != DOS_SIGNATURE) {
        error_ = "Invalid DOS (MZ) signature.";
        return false;
    }

    if (dos->e_lfanew < 0) {
        error_ = "Negative e_lfanew offset in DOS header.";
        return false;
    }

    size_t nt_offset = static_cast<size_t>(dos->e_lfanew);
    const auto* signature = read_struct<uint32_t>(nt_offset);
    if (!signature || *signature != NT_SIGNATURE) {
        error_ = "Invalid PE signature.";
        return false;
    }

    size_t file_hdr_offset = nt_offset + sizeof(uint32_t);
    const auto* file_hdr = read_struct<FileHeader>(file_hdr_offset);
    if (!file_hdr) {
        error_ = "Truncated PE File Header.";
        return false;
    }

    timestamp_ = file_hdr->time_date_stamp;

    size_t opt_hdr_offset = file_hdr_offset + sizeof(FileHeader);
    const auto* magic = read_struct<uint16_t>(opt_hdr_offset);
    if (!magic) {
        error_ = "Truncated Optional Header.";
        return false;
    }

    if (*magic == OPT_HDR64_MAGIC) {
        is_64bit_ = true;
        const auto* opt64 = read_struct<OptionalHeader64>(opt_hdr_offset);
        if (!opt64) {
            error_ = "Corrupted 64-bit Optional Header.";
            return false;
        }
        image_base_ = opt64->image_base;
        entry_point_rva_ = opt64->address_of_entry_point;
        dll_characteristics_ = opt64->dll_characteristics;
        std::memcpy(data_directories_, opt64->data_directory, sizeof(data_directories_));
    } else if (*magic == OPT_HDR32_MAGIC) {
        is_64bit_ = false;
        const auto* opt32 = read_struct<OptionalHeader32>(opt_hdr_offset);
        if (!opt32) {
            error_ = "Corrupted 32-bit Optional Header.";
            return false;
        }
        image_base_ = opt32->image_base;
        entry_point_rva_ = opt32->address_of_entry_point;
        dll_characteristics_ = opt32->dll_characteristics;
        std::memcpy(data_directories_, opt32->data_directory, sizeof(data_directories_));
    } else {
        error_ = "Unknown Optional Header magic value.";
        return false;
    }

    size_t section_table_offset = opt_hdr_offset + file_hdr->size_of_optional_header;
    uint16_t num_sections = file_hdr->number_of_sections;

    // Windows loader caps at 96
    if (num_sections > 96) {
        error_ = "Abnormal number of sections (> 96).";
        return false;
    }

    sections_.reserve(num_sections);
    for (uint16_t i = 0; i < num_sections; ++i) {
        size_t sec_offset = section_table_offset + (i * sizeof(SectionHeader));
        const auto* sec = read_struct<SectionHeader>(sec_offset);
        if (!sec) {
            error_ = "Truncated Section Header table.";
            return false;
        }

        size_t name_len = 0;
        while (name_len < 8 && sec->name[name_len] != '\0') {
            ++name_len;
        }
        std::string sec_name(sec->name, name_len);

        std::span<const uint8_t> sec_data{};
        if (sec->pointer_to_raw_data < buffer_.size() && sec->size_of_raw_data > 0) {
            size_t available = buffer_.size() - sec->pointer_to_raw_data;
            size_t clamped_size = std::min<size_t>(sec->size_of_raw_data, available);
            sec_data = buffer_.subspan(sec->pointer_to_raw_data, clamped_size);
        }

        sections_.push_back(SectionInfo{
            .name = std::move(sec_name),
            .virtual_address = sec->virtual_address,
            .virtual_size = sec->virtual_size,
            .raw_offset = sec->pointer_to_raw_data,
            .raw_size = sec->size_of_raw_data,
            .characteristics = sec->characteristics,
            .data = sec_data
        });
    }

    return true;
}

std::optional<uint32_t> PeParser::rva_to_offset(uint32_t rva) const noexcept {
    for (const auto& sec : sections_) {
        uint32_t sec_va_end = sec.virtual_address + std::max(sec.virtual_size, sec.raw_size);
        if (rva >= sec.virtual_address && rva < sec_va_end) {
            uint32_t delta = rva - sec.virtual_address;
            if (delta < sec.raw_size) {
                uint32_t file_offset = sec.raw_offset + delta;
                if (file_offset < buffer_.size()) {
                    return file_offset;
                }
            }
        }
    }
    return std::nullopt;
}

}