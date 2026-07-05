#include "type_check.hpp"

#include <algorithm>
#include <cctype>
#include <map>
#include <set>

namespace {

std::string lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

const std::map<std::string, std::set<std::string>>& extension_types() {
    static const std::map<std::string, std::set<std::string>> values{
        {".exe", {"PE/MZ"}},
        {".dll", {"PE/MZ"}},
        {".sys", {"PE/MZ"}},
        {".png", {"PNG"}},
        {".jpg", {"JPEG"}},
        {".jpeg", {"JPEG"}},
        {".gif", {"GIF"}},
        {".zip", {"ZIP"}},
        {".jar", {"ZIP"}},
        {".docx", {"ZIP"}},
        {".xlsx", {"ZIP"}},
        {".pptx", {"ZIP"}},
        {".pdf", {"PDF"}},
        {".rar", {"RAR"}},
        {".gz", {"GZIP"}},
        {".bmp", {"BMP"}},
        {".elf", {"ELF"}},
        {".so", {"ELF"}},
    };
    return values;
}

} // namespace

TypeCheckResult check_extension_signature(
    const std::filesystem::path& path,
    const FileSignature& signature) {
    TypeCheckResult result;
    result.extension = lower(path.extension().string());
    result.detected_type = signature.type;

    const auto found = extension_types().find(result.extension);
    if (found == extension_types().end()) {
        result.known_extension = false;
        result.matched = false;
        result.message = result.extension.empty()
            ? "file has no extension to compare"
            : "extension is not in the built-in mapping table";
        return result;
    }

    result.known_extension = true;
    result.matched = found->second.count(signature.type) > 0;
    result.message = result.matched
        ? "extension matches detected file signature"
        : "extension does not match detected file signature";
    return result;
}
