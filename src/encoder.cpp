#include "encoder.hpp"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace {

std::string bytes_to_hex(const std::vector<unsigned char>& bytes) {
    std::ostringstream output;
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        if (i != 0) {
            output << ' ';
        }
        output << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
               << static_cast<int>(bytes[i]);
    }
    return output.str();
}

std::string bytes_to_decimal(const std::vector<unsigned char>& bytes) {
    std::ostringstream output;
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        if (i != 0) {
            output << ' ';
        }
        output << static_cast<int>(bytes[i]);
    }
    return output.str();
}

std::vector<unsigned char> as_utf8_bytes(const std::string& input) {
    return {input.begin(), input.end()};
}

std::string lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

int hex_value(char ch) {
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }
    if (ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 10;
    }
    if (ch >= 'A' && ch <= 'F') {
        return ch - 'A' + 10;
    }
    return -1;
}

std::vector<unsigned int> utf8_to_codepoints(const std::string& input) {
    std::vector<unsigned int> codepoints;
    for (std::size_t i = 0; i < input.size();) {
        const auto c = static_cast<unsigned char>(input[i]);
        if ((c & 0x80) == 0) {
            codepoints.push_back(c);
            ++i;
        } else if ((c & 0xE0) == 0xC0 && i + 1 < input.size()) {
            codepoints.push_back(((c & 0x1F) << 6) |
                                 (static_cast<unsigned char>(input[i + 1]) & 0x3F));
            i += 2;
        } else if ((c & 0xF0) == 0xE0 && i + 2 < input.size()) {
            codepoints.push_back(((c & 0x0F) << 12) |
                                 ((static_cast<unsigned char>(input[i + 1]) & 0x3F) << 6) |
                                 (static_cast<unsigned char>(input[i + 2]) & 0x3F));
            i += 3;
        } else if ((c & 0xF8) == 0xF0 && i + 3 < input.size()) {
            codepoints.push_back(((c & 0x07) << 18) |
                                 ((static_cast<unsigned char>(input[i + 1]) & 0x3F) << 12) |
                                 ((static_cast<unsigned char>(input[i + 2]) & 0x3F) << 6) |
                                 (static_cast<unsigned char>(input[i + 3]) & 0x3F));
            i += 4;
        } else {
            codepoints.push_back(0xFFFD);
            ++i;
        }
    }
    return codepoints;
}

void append_le16(std::vector<unsigned char>& bytes, unsigned int value) {
    bytes.push_back(static_cast<unsigned char>(value & 0xFF));
    bytes.push_back(static_cast<unsigned char>((value >> 8) & 0xFF));
}

std::vector<unsigned char> as_utf16le_bytes(const std::string& input) {
    std::vector<unsigned char> bytes;
    for (auto codepoint : utf8_to_codepoints(input)) {
        if (codepoint <= 0xFFFF) {
            append_le16(bytes, codepoint);
        } else {
            codepoint -= 0x10000;
            append_le16(bytes, 0xD800 + ((codepoint >> 10) & 0x3FF));
            append_le16(bytes, 0xDC00 + (codepoint & 0x3FF));
        }
    }
    return bytes;
}

std::string base64_encode(const std::vector<unsigned char>& bytes) {
    static constexpr char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string output;

    for (std::size_t i = 0; i < bytes.size(); i += 3) {
        const auto b0 = bytes[i];
        const auto b1 = i + 1 < bytes.size() ? bytes[i + 1] : 0;
        const auto b2 = i + 2 < bytes.size() ? bytes[i + 2] : 0;

        output.push_back(alphabet[(b0 >> 2) & 0x3F]);
        output.push_back(alphabet[((b0 & 0x03) << 4) | ((b1 >> 4) & 0x0F)]);
        output.push_back(i + 1 < bytes.size() ? alphabet[((b1 & 0x0F) << 2) | ((b2 >> 6) & 0x03)] : '=');
        output.push_back(i + 2 < bytes.size() ? alphabet[b2 & 0x3F] : '=');
    }

    return output;
}

bool is_url_safe(unsigned char value) {
    return (value >= 'A' && value <= 'Z') ||
           (value >= 'a' && value <= 'z') ||
           (value >= '0' && value <= '9') ||
           value == '-' || value == '_' || value == '.' || value == '~';
}

std::string url_encode(const std::vector<unsigned char>& bytes) {
    std::ostringstream output;
    for (const auto byte : bytes) {
        if (is_url_safe(byte)) {
            output << static_cast<char>(byte);
        } else {
            output << '%' << std::hex << std::uppercase << std::setw(2)
                   << std::setfill('0') << static_cast<int>(byte);
        }
    }
    return output.str();
}

std::string c_escape(const std::vector<unsigned char>& bytes) {
    std::ostringstream output;
    for (const auto byte : bytes) {
        switch (byte) {
        case '\n':
            output << "\\n";
            break;
        case '\r':
            output << "\\r";
            break;
        case '\t':
            output << "\\t";
            break;
        case '\\':
            output << "\\\\";
            break;
        case '"':
            output << "\\\"";
            break;
        default:
            if (byte >= 0x20 && byte <= 0x7E) {
                output << static_cast<char>(byte);
            } else {
                output << "\\x" << std::hex << std::uppercase << std::setw(2)
                       << std::setfill('0') << static_cast<int>(byte);
            }
            break;
        }
    }
    return output.str();
}

std::vector<unsigned char> hex_decode(const std::string& input) {
    std::string compact;
    for (const auto ch : input) {
        if (!std::isspace(static_cast<unsigned char>(ch))) {
            compact.push_back(ch);
        }
    }
    if (compact.size() % 2 != 0) {
        throw std::runtime_error("hex input must contain an even number of digits");
    }

    std::vector<unsigned char> bytes;
    for (std::size_t i = 0; i < compact.size(); i += 2) {
        const auto high = hex_value(compact[i]);
        const auto low = hex_value(compact[i + 1]);
        if (high < 0 || low < 0) {
            throw std::runtime_error("hex input contains a non-hex digit");
        }
        bytes.push_back(static_cast<unsigned char>((high << 4) | low));
    }
    return bytes;
}

int base64_value(char ch) {
    if (ch >= 'A' && ch <= 'Z') {
        return ch - 'A';
    }
    if (ch >= 'a' && ch <= 'z') {
        return ch - 'a' + 26;
    }
    if (ch >= '0' && ch <= '9') {
        return ch - '0' + 52;
    }
    if (ch == '+') {
        return 62;
    }
    if (ch == '/') {
        return 63;
    }
    return -1;
}

std::vector<unsigned char> base64_decode(const std::string& input) {
    std::string compact;
    for (const auto ch : input) {
        if (!std::isspace(static_cast<unsigned char>(ch))) {
            compact.push_back(ch);
        }
    }
    if (compact.size() % 4 != 0) {
        throw std::runtime_error("base64 input length must be a multiple of 4");
    }

    std::vector<unsigned char> bytes;
    for (std::size_t i = 0; i < compact.size(); i += 4) {
        const auto c0 = base64_value(compact[i]);
        const auto c1 = base64_value(compact[i + 1]);
        const auto c2 = compact[i + 2] == '=' ? 0 : base64_value(compact[i + 2]);
        const auto c3 = compact[i + 3] == '=' ? 0 : base64_value(compact[i + 3]);
        if (c0 < 0 || c1 < 0 || c2 < 0 || c3 < 0) {
            throw std::runtime_error("base64 input contains an invalid character");
        }

        bytes.push_back(static_cast<unsigned char>((c0 << 2) | (c1 >> 4)));
        if (compact[i + 2] != '=') {
            bytes.push_back(static_cast<unsigned char>(((c1 & 0x0F) << 4) | (c2 >> 2)));
        }
        if (compact[i + 3] != '=') {
            bytes.push_back(static_cast<unsigned char>(((c2 & 0x03) << 6) | c3));
        }
    }
    return bytes;
}

std::vector<unsigned char> url_decode(const std::string& input) {
    std::vector<unsigned char> bytes;
    for (std::size_t i = 0; i < input.size(); ++i) {
        if (input[i] == '%' && i + 2 < input.size()) {
            const auto high = hex_value(input[i + 1]);
            const auto low = hex_value(input[i + 2]);
            if (high < 0 || low < 0) {
                throw std::runtime_error("URL encoding contains an invalid percent escape");
            }
            bytes.push_back(static_cast<unsigned char>((high << 4) | low));
            i += 2;
        } else if (input[i] == '+') {
            bytes.push_back(' ');
        } else {
            bytes.push_back(static_cast<unsigned char>(input[i]));
        }
    }
    return bytes;
}

std::vector<unsigned char> c_unescape(const std::string& input) {
    std::vector<unsigned char> bytes;
    for (std::size_t i = 0; i < input.size(); ++i) {
        if (input[i] != '\\') {
            bytes.push_back(static_cast<unsigned char>(input[i]));
            continue;
        }
        if (i + 1 >= input.size()) {
            throw std::runtime_error("C escape ends with a trailing backslash");
        }

        const auto esc = input[++i];
        switch (esc) {
        case 'n':
            bytes.push_back('\n');
            break;
        case 'r':
            bytes.push_back('\r');
            break;
        case 't':
            bytes.push_back('\t');
            break;
        case '\\':
            bytes.push_back('\\');
            break;
        case '"':
            bytes.push_back('"');
            break;
        case 'x':
            if (i + 2 >= input.size()) {
                throw std::runtime_error("C hex escape requires two hex digits");
            } else {
                const auto high = hex_value(input[i + 1]);
                const auto low = hex_value(input[i + 2]);
                if (high < 0 || low < 0) {
                    throw std::runtime_error("C hex escape contains a non-hex digit");
                }
                bytes.push_back(static_cast<unsigned char>((high << 4) | low));
                i += 2;
            }
            break;
        default:
            bytes.push_back(static_cast<unsigned char>(esc));
            break;
        }
    }
    return bytes;
}

std::vector<unsigned char> decimal_decode(const std::string& input) {
    std::string normalized = input;
    std::replace(normalized.begin(), normalized.end(), ',', ' ');
    std::istringstream stream(normalized);
    std::vector<unsigned char> bytes;
    std::string token;
    while (stream >> token) {
        const auto value = std::stoul(token, nullptr, 0);
        if (value > 255) {
            throw std::runtime_error("decimal byte value is greater than 255");
        }
        bytes.push_back(static_cast<unsigned char>(value));
    }
    return bytes;
}

void append_utf8(std::string& output, unsigned int codepoint) {
    if (codepoint <= 0x7F) {
        output.push_back(static_cast<char>(codepoint));
    } else if (codepoint <= 0x7FF) {
        output.push_back(static_cast<char>(0xC0 | (codepoint >> 6)));
        output.push_back(static_cast<char>(0x80 | (codepoint & 0x3F)));
    } else if (codepoint <= 0xFFFF) {
        output.push_back(static_cast<char>(0xE0 | (codepoint >> 12)));
        output.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3F)));
        output.push_back(static_cast<char>(0x80 | (codepoint & 0x3F)));
    } else {
        output.push_back(static_cast<char>(0xF0 | (codepoint >> 18)));
        output.push_back(static_cast<char>(0x80 | ((codepoint >> 12) & 0x3F)));
        output.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3F)));
        output.push_back(static_cast<char>(0x80 | (codepoint & 0x3F)));
    }
}

std::string utf16le_bytes_to_utf8(const std::vector<unsigned char>& bytes) {
    if (bytes.size() % 2 != 0) {
        throw std::runtime_error("UTF-16LE byte input must have an even length");
    }

    std::string output;
    for (std::size_t i = 0; i < bytes.size(); i += 2) {
        auto unit = static_cast<unsigned int>(bytes[i]) |
                    (static_cast<unsigned int>(bytes[i + 1]) << 8);
        if (unit >= 0xD800 && unit <= 0xDBFF) {
            if (i + 3 >= bytes.size()) {
                throw std::runtime_error("UTF-16LE high surrogate has no low surrogate");
            }
            const auto low = static_cast<unsigned int>(bytes[i + 2]) |
                             (static_cast<unsigned int>(bytes[i + 3]) << 8);
            if (low < 0xDC00 || low > 0xDFFF) {
                throw std::runtime_error("UTF-16LE surrogate pair is invalid");
            }
            const auto codepoint = 0x10000 + (((unit - 0xD800) << 10) | (low - 0xDC00));
            append_utf8(output, codepoint);
            i += 2;
        } else {
            append_utf8(output, unit);
        }
    }
    return output;
}

} // namespace

EncodedText encode_text(const std::string& input) {
    const auto utf8 = as_utf8_bytes(input);
    const auto utf16le = as_utf16le_bytes(input);

    EncodedText result;
    result.input = input;
    result.utf8_hex = bytes_to_hex(utf8);
    result.utf16le_hex = bytes_to_hex(utf16le);
    result.decimal_bytes = bytes_to_decimal(utf8);
    result.base64 = base64_encode(utf8);
    result.url_encoded = url_encode(utf8);
    result.c_escaped = c_escape(utf8);
    return result;
}

DecodedText decode_text(const std::string& type, const std::string& input) {
    const auto normalized_type = lower(type);
    std::vector<unsigned char> bytes;
    std::string text;

    if (normalized_type == "hex") {
        bytes = hex_decode(input);
        text = std::string(bytes.begin(), bytes.end());
    } else if (normalized_type == "base64" || normalized_type == "b64") {
        bytes = base64_decode(input);
        text = std::string(bytes.begin(), bytes.end());
    } else if (normalized_type == "url" || normalized_type == "urlencoded") {
        bytes = url_decode(input);
        text = std::string(bytes.begin(), bytes.end());
    } else if (normalized_type == "c" || normalized_type == "escape" || normalized_type == "c-escape") {
        bytes = c_unescape(input);
        text = std::string(bytes.begin(), bytes.end());
    } else if (normalized_type == "decimal" || normalized_type == "dec") {
        bytes = decimal_decode(input);
        text = std::string(bytes.begin(), bytes.end());
    } else if (normalized_type == "utf16le-hex" || normalized_type == "utf-16le-hex") {
        bytes = hex_decode(input);
        text = utf16le_bytes_to_utf8(bytes);
    } else {
        throw std::runtime_error("unsupported decode type: " + type);
    }

    DecodedText result;
    result.type = normalized_type;
    result.text = text;
    result.utf8_hex = bytes_to_hex(as_utf8_bytes(text));
    result.decimal_bytes = bytes_to_decimal(as_utf8_bytes(text));
    result.c_escaped = c_escape(as_utf8_bytes(text));
    return result;
}
