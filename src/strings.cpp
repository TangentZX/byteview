#include "strings.hpp"

#include <cctype>

std::vector<ExtractedString> extract_ascii_strings(
    const std::vector<std::uint8_t>& bytes,
    std::size_t min_length) {
    std::vector<ExtractedString> strings;
    std::string current;
    std::size_t start = 0;

    for (std::size_t i = 0; i < bytes.size(); ++i) {
        if (std::isprint(bytes[i]) || bytes[i] == '\t') {
            if (current.empty()) {
                start = i;
            }
            current.push_back(static_cast<char>(bytes[i]));
            continue;
        }

        if (current.size() >= min_length) {
            strings.push_back(ExtractedString{start, current});
        }
        current.clear();
    }

    if (current.size() >= min_length) {
        strings.push_back(ExtractedString{start, current});
    }

    return strings;
}
