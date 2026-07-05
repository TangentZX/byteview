#include "png_parser.hpp"

#include <algorithm>
#include <array>
#include <stdexcept>

namespace {

std::uint32_t read_be32(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
    if (offset + 4 > bytes.size()) {
        throw std::runtime_error("unexpected end of PNG data");
    }

    return (static_cast<std::uint32_t>(bytes[offset]) << 24) |
           (static_cast<std::uint32_t>(bytes[offset + 1]) << 16) |
           (static_cast<std::uint32_t>(bytes[offset + 2]) << 8) |
           static_cast<std::uint32_t>(bytes[offset + 3]);
}

bool has_png_signature(const std::vector<std::uint8_t>& bytes) {
    static constexpr std::array<std::uint8_t, 8> signature{
        0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A};

    return bytes.size() >= signature.size() &&
           std::equal(signature.begin(), signature.end(), bytes.begin());
}

} // namespace

PngInfo parse_png(const std::vector<std::uint8_t>& bytes) {
    PngInfo info;
    if (!has_png_signature(bytes)) {
        return info;
    }

    info.valid = true;
    std::size_t offset = 8;

    while (offset + 12 <= bytes.size()) {
        const auto chunk_offset = offset;
        const auto length = read_be32(bytes, offset);
        offset += 4;

        std::string type;
        for (std::size_t i = 0; i < 4; ++i) {
            type.push_back(static_cast<char>(bytes[offset + i]));
        }
        offset += 4;

        const auto data_end = offset + length;
        if (data_end + 4 > bytes.size()) {
            throw std::runtime_error("PNG chunk extends beyond file size");
        }

        offset = data_end;
        const auto crc = read_be32(bytes, offset);
        offset += 4;

        info.chunks.push_back(PngChunk{chunk_offset, length, type, crc});
        if (type == "IEND") {
            break;
        }
    }

    return info;
}
