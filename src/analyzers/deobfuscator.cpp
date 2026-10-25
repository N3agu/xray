#include "analyzers/deobfuscator.hpp"
#include <algorithm>
#include <array>
#include <cctype>

namespace xray::analyzers {

static const std::vector<std::string> KNOWN_CRIBS = {
    "http://",
    "https://",
    "powershell",
    "cmd.exe",
    "VirtualAlloc",
    "VirtualProtect",
    "LoadLibrary",
    "GetProcAddress",
    "CreateProcess",
    "WinExec",
    "WScript.Shell",
    "RegOpenKey"
};

std::string Deobfuscator::type_to_string(DeobfuscationType type) {
    switch (type) {
        case DeobfuscationType::Base64:   return "Base64";
        case DeobfuscationType::Xor1Byte: return "XOR (1-Byte)";
        case DeobfuscationType::Xor2Byte: return "XOR (2-Byte)";
    }
    return "Unknown";
}

std::string Deobfuscator::expand_xor_string(std::span<const uint8_t> buffer, size_t match_offset, size_t match_len, uint16_t key, bool is_2byte) {
    size_t start = match_offset;
    size_t end = match_offset + match_len;

    auto decrypt_byte = [&](size_t idx) -> uint8_t {
        if (!is_2byte) {
            return buffer[idx] ^ static_cast<uint8_t>(key & 0xFF);
        }
        uint8_t k = (idx % 2 == 0) ? static_cast<uint8_t>(key & 0xFF) : static_cast<uint8_t>((key >> 8) & 0xFF);
        return buffer[idx] ^ k;
    };

    while (start > 0) {
        uint8_t dec = decrypt_byte(start - 1);
        if (dec >= 0x20 && dec <= 0x7E) {
            --start;
        } else {
            break;
        }
    }

    while (end < buffer.size()) {
        uint8_t dec = decrypt_byte(end);
        if (dec >= 0x20 && dec <= 0x7E) {
            ++end;
        } else {
            break;
        }
    }

    std::string result;
    result.reserve(end - start);
    for (size_t i = start; i < end; ++i) {
        result.push_back(static_cast<char>(decrypt_byte(i)));
    }
    return result;
}

void Deobfuscator::scan_xor_1byte(std::span<const uint8_t> buffer, DeobfuscationResult& result) {
    if (buffer.empty()) return;

    for (uint32_t k = 1; k <= 0xFF; ++k) {
        uint8_t key = static_cast<uint8_t>(k);

        for (const auto& crib : KNOWN_CRIBS) {
            if (crib.size() > buffer.size()) continue;

            std::vector<uint8_t> enc_crib(crib.size());
            for (size_t i = 0; i < crib.size(); ++i) {
                enc_crib[i] = static_cast<uint8_t>(crib[i]) ^ key;
            }

            auto it = std::search(buffer.begin(), buffer.end(), enc_crib.begin(), enc_crib.end());
            while (it != buffer.end()) {
                size_t offset = std::distance(buffer.begin(), it);
                std::string full_str = expand_xor_string(buffer, offset, crib.size(), key, false);

                bool duplicate = false;
                for (const auto& existing : result.findings) {
                    if (existing.type == DeobfuscationType::Xor1Byte && existing.offset == offset && existing.key == key) {
                        duplicate = true;
                        break;
                    }
                }

                if (!duplicate) {
                    result.findings.push_back({
                        .type = DeobfuscationType::Xor1Byte,
                        .offset = static_cast<uint32_t>(offset),
                        .key = key,
                        .matched_crib = crib,
                        .decoded_value = full_str
                    });
                }

                it = std::search(it + enc_crib.size(), buffer.end(), enc_crib.begin(), enc_crib.end());
            }
        }
    }
}

void Deobfuscator::scan_xor_2byte(std::span<const uint8_t> buffer, DeobfuscationResult& result) {
    if (buffer.size() < 4) return;

    for (const auto& crib : KNOWN_CRIBS) {
        if (crib.size() < 4 || crib.size() > buffer.size()) continue;

        for (size_t i = 0; i + crib.size() <= buffer.size(); ++i) {
            uint8_t k0 = (i % 2 == 0) ? (buffer[i] ^ static_cast<uint8_t>(crib[0])) : (buffer[i] ^ static_cast<uint8_t>(crib[1]));
            uint8_t k1 = (i % 2 == 0) ? (buffer[i + 1] ^ static_cast<uint8_t>(crib[1])) : (buffer[i + 1] ^ static_cast<uint8_t>(crib[0]));

            if (k0 == 0 && k1 == 0) continue;
            if (k0 == k1) continue;

            bool matched = true;
            for (size_t j = 2; j < crib.size(); ++j) {
                uint8_t expected_key = ((i + j) % 2 == 0) ? k0 : k1;
                if ((buffer[i + j] ^ expected_key) != static_cast<uint8_t>(crib[j])) {
                    matched = false;
                    break;
                }
            }

            if (matched) {
                uint16_t full_key = static_cast<uint16_t>(k0) | (static_cast<uint16_t>(k1) << 8);
                std::string full_str = expand_xor_string(buffer, i, crib.size(), full_key, true);

                bool duplicate = false;
                for (const auto& existing : result.findings) {
                    if (existing.type == DeobfuscationType::Xor2Byte && existing.offset == static_cast<uint32_t>(i)) {
                        duplicate = true;
                        break;
                    }
                }

                if (!duplicate) {
                    result.findings.push_back({
                        .type = DeobfuscationType::Xor2Byte,
                        .offset = static_cast<uint32_t>(i),
                        .key = full_key,
                        .matched_crib = crib,
                        .decoded_value = full_str
                    });
                }
                i += crib.size() - 1;
            }
        }
    }
}

std::string Deobfuscator::decode_base64_block(std::string_view encoded) {
    static const std::string b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::vector<int> table(256, -1);
    for (size_t i = 0; i < b64.size(); ++i) {
        table[static_cast<uint8_t>(b64[i])] = static_cast<int>(i);
    }

    std::string decoded;
    int val = 0;
    int valb = -8;

    for (char c : encoded) {
        if (c == '=') break;
        uint8_t uc = static_cast<uint8_t>(c);
        if (table[uc] == -1) return "";
        val = (val << 6) + table[uc];
        valb += 6;
        if (valb >= 0) {
            decoded.push_back(static_cast<char>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return decoded;
}

void Deobfuscator::scan_base64(std::span<const uint8_t> buffer, DeobfuscationResult& result) {
    std::string current;
    size_t start_offset = 0;

    auto is_b64 = [](char c) -> bool {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
               (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
    };

    for (size_t i = 0; i < buffer.size(); ++i) {
        char c = static_cast<char>(buffer[i]);
        if (is_b64(c)) {
            if (current.empty()) {
                start_offset = i;
            }
            current.push_back(c);
        } else {
            if (current.size() >= 16) {
                std::string decoded = decode_base64_block(current);
                
                size_t printable_count = 0;
                for (char dc : decoded) {
                    if (dc >= 0x20 && dc <= 0x7E) ++printable_count;
                }

                if (!decoded.empty() && printable_count >= 5 && printable_count >= (decoded.size() * 8 / 10)) {
                    result.findings.push_back({
                        .type = DeobfuscationType::Base64,
                        .offset = static_cast<uint32_t>(start_offset),
                        .key = 0,
                        .matched_crib = "None",
                        .decoded_value = decoded
                    });
                }
            }
            current.clear();
        }
    }
}

DeobfuscationResult Deobfuscator::analyze(const pe::PeParser& parser) {
    DeobfuscationResult result;
    auto buffer = parser.raw_buffer();

    scan_xor_1byte(buffer, result);
    scan_xor_2byte(buffer, result);
    scan_base64(buffer, result);

    return result;
}

}