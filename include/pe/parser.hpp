#pragma once
#include "pe/structures.hpp"
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace xray::pe {

struct SectionInfo {
    std::string name;
    uint32_t virtual_address;
    uint32_t virtual_size;
    uint32_t raw_offset;
    uint32_t raw_size;
    uint32_t characteristics;
    std::span<const uint8_t> data;
};

class PeParser {
public:
    explicit PeParser(std::span<const uint8_t> buffer);

    [[nodiscard]] bool is_valid() const noexcept { return valid_; }
    [[nodiscard]] bool is_64bit() const noexcept { return is_64bit_; }
    [[nodiscard]] const std::string& error_message() const noexcept { return error_; }
    
    [[nodiscard]] uint64_t image_base() const noexcept { return image_base_; }
    [[nodiscard]] uint32_t entry_point_rva() const noexcept { return entry_point_rva_; }
    [[nodiscard]] const std::vector<SectionInfo>& sections() const noexcept { return sections_; }
    [[nodiscard]] std::span<const uint8_t> raw_buffer() const noexcept { return buffer_; }
    
    [[nodiscard]] const DataDirectory& import_directory() const noexcept { 
        return data_directories_[DIRECTORY_ENTRY_IMPORT]; 
    }
    [[nodiscard]] const DataDirectory& tls_directory() const noexcept { 
        return data_directories_[DIRECTORY_ENTRY_TLS]; 
    }

    [[nodiscard]] std::optional<uint32_t> rva_to_offset(uint32_t rva) const noexcept;

    template <typename T>
    [[nodiscard]] const T* read_struct(size_t offset) const noexcept {
        if (offset > buffer_.size() || sizeof(T) > (buffer_.size() - offset)) {
            return nullptr;
        }
        return reinterpret_cast<const T*>(buffer_.data() + offset);
    }

    [[nodiscard]] const char* read_string(size_t offset, size_t max_len = 256) const noexcept {
        if (offset >= buffer_.size()) {
            return nullptr;
        }
        const char* start = reinterpret_cast<const char*>(buffer_.data() + offset);
        size_t available = buffer_.size() - offset;
        size_t search_len = available < max_len ? available : max_len;
        for (size_t i = 0; i < search_len; ++i) {
            if (start[i] == '\0') {
                return start;
            }
        }
        return nullptr;
    }

private:
    bool parse();

    std::span<const uint8_t> buffer_;
    bool valid_ = false;
    bool is_64bit_ = false;
    std::string error_;

    uint64_t image_base_ = 0;
    uint32_t entry_point_rva_ = 0;
    DataDirectory data_directories_[16]{};
    std::vector<SectionInfo> sections_;
};

}