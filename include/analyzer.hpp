#pragma once

#include <cstdint>
#include <string>
#include <vector>

double shannon_entropy(const std::vector<std::uint8_t>& bytes);
std::vector<std::size_t> find_pattern(
    const std::vector<std::uint8_t>& bytes,
    const std::vector<std::uint8_t>& pattern);
std::vector<std::uint8_t> parse_hex_pattern(const std::string& pattern);
