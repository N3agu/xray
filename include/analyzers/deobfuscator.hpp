#pragma once
#include "pe/parser.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace xray::analyzers {

enum class DeobfuscationType {
    Base64,
    Xor1Byte,
    Xor2Byte,
    XorWide1Byte
};

struct DeobfuscatedString {
    DeobfuscationType type;
    uint32_t offset;
    uint32_t key;
    std::string matched_crib;
    std::string decoded_value;
};

struct DeobfuscationResult {
    std::vector<DeobfuscatedString> findings;
};

class Deobfuscator {
public:
    static DeobfuscationResult analyze(const pe::PeParser& parser);
    static std::string type_to_string(DeobfuscationType type);

private:
    static void scan_xor_1byte(std::span<const uint8_t> buffer, DeobfuscationResult& result);
    static void scan_xor_wide_1byte(std::span<const uint8_t> buffer, DeobfuscationResult& result);
    static void scan_xor_2byte(std::span<const uint8_t> buffer, DeobfuscationResult& result);
    static void scan_base64(std::span<const uint8_t> buffer, DeobfuscationResult& result);
    static std::string expand_xor_string(std::span<const uint8_t> buffer, size_t match_offset, size_t match_len, uint16_t key, bool is_2byte);
    static std::string decode_base64_block(std::string_view encoded);
};

}