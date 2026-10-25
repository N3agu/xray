#include "core/mapped_file.hpp"
#include <stdexcept>

#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>
#else
    #include <fcntl.h>
    #include <sys/mman.h>
    #include <sys/stat.h>
    #include <unistd.h>
#endif

namespace xray::core {

MappedFile::MappedFile(const std::filesystem::path& path) {
#ifdef _WIN32
    file_handle_ = CreateFileW(
        path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr
    );
    if (file_handle_ == INVALID_HANDLE_VALUE) {
        file_handle_ = nullptr;
        return;
    }

    LARGE_INTEGER file_size;
    if (!GetFileSizeEx(file_handle_, &file_size) || file_size.QuadPart == 0) {
        cleanup();
        return;
    }
    size_ = static_cast<size_t>(file_size.QuadPart);

    mapping_handle_ = CreateFileMappingW(file_handle_, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!mapping_handle_) {
        cleanup();
        return;
    }

    data_ = static_cast<const uint8_t*>(MapViewOfFile(mapping_handle_, FILE_MAP_READ, 0, 0, 0));
    if (!data_) {
        cleanup();
    }
#else
    fd_ = open(path.c_str(), O_RDONLY);
    if (fd_ == -1) return;

    struct stat sb{};
    if (fstat(fd_, &sb) == -1 || sb.st_size == 0) {
        cleanup();
        return;
    }
    size_ = static_cast<size_t>(sb.st_size);

    void* mapped = mmap(nullptr, size_, PROT_READ, MAP_PRIVATE, fd_, 0);
    if (mapped == MAP_FAILED) {
        cleanup();
        return;
    }
    data_ = static_cast<const uint8_t*>(mapped);
#endif
}

MappedFile::~MappedFile() {
    cleanup();
}

MappedFile::MappedFile(MappedFile&& other) noexcept
    : data_(other.data_), size_(other.size_)
#ifdef _WIN32
    , file_handle_(other.file_handle_), mapping_handle_(other.mapping_handle_)
#else
    , fd_(other.fd_)
#endif
{
    other.data_ = nullptr;
    other.size_ = 0;
#ifdef _WIN32
    other.file_handle_ = nullptr;
    other.mapping_handle_ = nullptr;
#else
    other.fd_ = -1;
#endif
}

MappedFile& MappedFile::operator=(MappedFile&& other) noexcept {
    if (this != &other) {
        cleanup();
        data_ = other.data_;
        size_ = other.size_;
#ifdef _WIN32
        file_handle_ = other.file_handle_;
        mapping_handle_ = other.mapping_handle_;
        other.file_handle_ = nullptr;
        other.mapping_handle_ = nullptr;
#else
        fd_ = other.fd_;
        other.fd_ = -1;
#endif
        other.data_ = nullptr;
        other.size_ = 0;
    }
    return *this;
}

void MappedFile::cleanup() noexcept {
#ifdef _WIN32
    if (data_) UnmapViewOfFile(data_);
    if (mapping_handle_) CloseHandle(mapping_handle_);
    if (file_handle_) CloseHandle(file_handle_);
    file_handle_ = nullptr;
    mapping_handle_ = nullptr;
#else
    if (data_ && data_ != MAP_FAILED) {
        munmap(const_cast<uint8_t*>(data_), size_);
    }
    if (fd_ != -1) close(fd_);
    fd_ = -1;
#endif
    data_ = nullptr;
    size_ = 0;
}

}