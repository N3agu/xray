#pragma once
#include <cstdint>
#include <span>
#include <string>
#include <filesystem>

namespace xray::core {

class MappedFile {
public:
    explicit MappedFile(const std::filesystem::path& path);
    ~MappedFile();

    MappedFile(const MappedFile&) = delete;
    MappedFile& operator=(const MappedFile&) = delete;

    MappedFile(MappedFile&& other) noexcept;
    MappedFile& operator=(MappedFile&& other) noexcept;

    [[nodiscard]] bool is_valid() const noexcept { return data_ != nullptr; }
    [[nodiscard]] std::span<const uint8_t> span() const noexcept { return {data_, size_}; }
    [[nodiscard]] size_t size() const noexcept { return size_; }

private:
    void cleanup() noexcept;

    const uint8_t* data_ = nullptr;
    size_t size_ = 0;

#ifdef _WIN32
    void* file_handle_ = nullptr;
    void* mapping_handle_ = nullptr;
#else
    int fd_ = -1;
#endif
};

}