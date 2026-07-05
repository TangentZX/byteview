#include "signature.hpp"

#include <algorithm>

namespace {

bool starts_with(const std::vector<std::uint8_t>& bytes, std::initializer_list<std::uint8_t> magic) {
    if (bytes.size() < magic.size()) {
        return false;
    }
    return std::equal(magic.begin(), magic.end(), bytes.begin());
}

} // namespace

FileSignature detect_signature(const std::vector<std::uint8_t>& bytes) {
    if (starts_with(bytes, {0x7F, 'E', 'L', 'F'})) {
        return {"ELF", "Executable and Linkable Format binary"};
    }
    if (starts_with(bytes, {'M', 'Z'})) {
        return {"PE/MZ", "Windows executable or DOS MZ format"};
    }
    if (starts_with(bytes, {0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A})) {
        return {"PNG", "Portable Network Graphics image"};
    }
    if (starts_with(bytes, {0xFF, 0xD8, 0xFF})) {
        return {"JPEG", "JPEG image"};
    }
    if (starts_with(bytes, {'G', 'I', 'F', '8'})) {
        return {"GIF", "Graphics Interchange Format image"};
    }
    if (starts_with(bytes, {'P', 'K', 0x03, 0x04})) {
        return {"ZIP", "ZIP archive or ZIP-based document"};
    }
    if (starts_with(bytes, {'%', 'P', 'D', 'F'})) {
        return {"PDF", "Portable Document Format"};
    }
    if (starts_with(bytes, {'R', 'a', 'r', '!', 0x1A, 0x07})) {
        return {"RAR", "RAR archive"};
    }
    if (starts_with(bytes, {0x1F, 0x8B})) {
        return {"GZIP", "Gzip compressed data"};
    }
    if (starts_with(bytes, {'B', 'M'})) {
        return {"BMP", "Bitmap image"};
    }
    return {"Unknown", "No known signature matched"};
}
