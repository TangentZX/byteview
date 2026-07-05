#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct ExtractedString {
    std::size_t offset{};
    std::string value;
};

std::vector<ExtractedString> extract_ascii_strings(
    const std::vector<std::uint8_t>& bytes,
    std::size_t min_length = 4);
