#pragma once

#include <string>
#include <vector>

struct EncodedText {
    std::string input;
    std::string utf8_hex;
    std::string utf16le_hex;
    std::string decimal_bytes;
    std::string base64;
    std::string url_encoded;
    std::string c_escaped;
};

struct DecodedText {
    std::string type;
    std::string text;
    std::string utf8_hex;
    std::string decimal_bytes;
    std::string c_escaped;
};

EncodedText encode_text(const std::string& input);
DecodedText decode_text(const std::string& type, const std::string& input);
