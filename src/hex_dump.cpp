#include "hex_dump.hpp"

#include <algorithm>
#include <cctype>
#include <iomanip>

namespace {

char printable(std::uint8_t value) {
    return std::isprint(value) ? static_cast<char>(value) : '.';
}

} // namespace

void print_hex_dump(
    const std::vector<std::uint8_t>& bytes,
    std::ostream& output,
    std::size_t offset,
    std::size_t length,
    std::size_t width) {
    if (offset >= bytes.size()) {
        return;
    }

    const auto end = std::min(bytes.size(), offset + length);

    for (std::size_t row = offset; row < end; row += width) {
        const auto row_end = std::min(end, row + width);

        output << std::hex << std::setw(8) << std::setfill('0') << row << "  ";

        for (std::size_t i = row; i < row + width; ++i) {
            if (i < row_end) {
                output << std::setw(2) << static_cast<int>(bytes[i]) << ' ';
            } else {
                output << "   ";
            }

            if ((i - row + 1) == width / 2) {
                output << ' ';
            }
        }

        output << " |";
        for (std::size_t i = row; i < row_end; ++i) {
            output << printable(bytes[i]);
        }
        output << "|\n";
    }

    output << std::dec << std::setfill(' ');
}
