#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct PngChunk {
    std::size_t offset{};
    std::uint32_t length{};
    std::string type;
    std::uint32_t crc{};
};

struct PngInfo {
    bool valid{};
    std::vector<PngChunk> chunks;
};

PngInfo parse_png(const std::vector<std::uint8_t>& bytes);
