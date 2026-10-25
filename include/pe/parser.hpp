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
    [[nodiscard]] std::optional<uint32_t> rva_to_offset(uint32_t rva) const noexcept;

    template <typename T>
    [[nodiscard]] const T* read_struct(size_t offset) const noexcept {
        if (offset > buffer_.size() || sizeof(T) > (buffer_.size() - offset)) {
            return nullptr;
        }
        return reinterpret_cast<const T*>(buffer_.data() + offset);
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