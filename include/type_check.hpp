#pragma once

#include "signature.hpp"

#include <filesystem>
#include <string>

struct TypeCheckResult {
    std::string extension;
    std::string detected_type;
    bool known_extension{};
    bool matched{};
    std::string message;
};

TypeCheckResult check_extension_signature(
    const std::filesystem::path& path,
    const FileSignature& signature);
