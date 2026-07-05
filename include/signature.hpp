#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct FileSignature {
    std::string type;
    std::string description;
};

FileSignature detect_signature(const std::vector<std::uint8_t>& bytes);
