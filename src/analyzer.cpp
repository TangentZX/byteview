#include "analyzer.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cctype>
#include <sstream>
#include <stdexcept>

double shannon_entropy(const std::vector<std::uint8_t>& bytes) {
    if (bytes.empty()) {
        return 0.0;
    }

    std::array<std::size_t, 256> counts{};
    for (const auto byte : bytes) {
        ++counts[byte];
    }

    double entropy = 0.0;
    const auto size = static_cast<double>(bytes.size());
    for (const auto count : counts) {
        if (count == 0) {
            continue;
        }
        const auto p = static_cast<double>(count) / size;
        entropy -= p * std::log2(p);
    }

    return entropy;
}

std::vector<std::size_t> find_pattern(
    const std::vector<std::uint8_t>& bytes,
    const std::vector<std::uint8_t>& pattern) {
    std::vector<std::size_t> offsets;
    if (pattern.empty() || pattern.size() > bytes.size()) {
        return offsets;
    }

    for (std::size_t i = 0; i + pattern.size() <= bytes.size(); ++i) {
        if (std::equal(pattern.begin(), pattern.end(), bytes.begin() + static_cast<std::ptrdiff_t>(i))) {
            offsets.push_back(i);
        }
    }

    return offsets;
}

std::vector<std::uint8_t> parse_hex_pattern(const std::string& pattern) {
    std::string compact;
    for (const auto ch : pattern) {
        if (!std::isspace(static_cast<unsigned char>(ch))) {
            compact.push_back(ch);
        }
    }

    if (compact.size() % 2 != 0) {
        throw std::runtime_error("hex pattern must contain an even number of digits");
    }

    std::vector<std::uint8_t> bytes;
    for (std::size_t i = 0; i < compact.size(); i += 2) {
        const auto hi = compact[i];
        const auto lo = compact[i + 1];
        if (!std::isxdigit(static_cast<unsigned char>(hi)) ||
            !std::isxdigit(static_cast<unsigned char>(lo))) {
            throw std::runtime_error("hex pattern contains a non-hex digit");
        }

        const auto value = std::stoul(compact.substr(i, 2), nullptr, 16);
        bytes.push_back(static_cast<std::uint8_t>(value));
    }

    return bytes;
}
