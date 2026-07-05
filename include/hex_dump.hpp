#pragma once

#include <cstdint>
#include <ostream>
#include <vector>

void print_hex_dump(
    const std::vector<std::uint8_t>& bytes,
    std::ostream& output,
    std::size_t offset = 0,
    std::size_t length = 256,
    std::size_t width = 16);
