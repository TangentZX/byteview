#include "pe_parser.hpp"

#include <algorithm>
#include <stdexcept>

namespace {

std::uint16_t read_le16(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
    if (offset + 2 > bytes.size()) {
        throw std::runtime_error("unexpected end of PE data");
    }
    return static_cast<std::uint16_t>(bytes[offset]) |
           (static_cast<std::uint16_t>(bytes[offset + 1]) << 8);
}

std::uint32_t read_le32(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
    if (offset + 4 > bytes.size()) {
        throw std::runtime_error("unexpected end of PE data");
    }
    return static_cast<std::uint32_t>(bytes[offset]) |
           (static_cast<std::uint32_t>(bytes[offset + 1]) << 8) |
           (static_cast<std::uint32_t>(bytes[offset + 2]) << 16) |
           (static_cast<std::uint32_t>(bytes[offset + 3]) << 24);
}

std::uint64_t read_le64(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
    const auto low = static_cast<std::uint64_t>(read_le32(bytes, offset));
    const auto high = static_cast<std::uint64_t>(read_le32(bytes, offset + 4));
    return low | (high << 32);
}

std::string read_section_name(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
    std::string name;
    for (std::size_t i = 0; i < 8 && offset + i < bytes.size(); ++i) {
        if (bytes[offset + i] == 0) {
            break;
        }
        name.push_back(static_cast<char>(bytes[offset + i]));
    }
    return name;
}

} // namespace

PeInfo parse_pe(const std::vector<std::uint8_t>& bytes) {
    PeInfo info;
    if (bytes.size() < 0x40 || bytes[0] != 'M' || bytes[1] != 'Z') {
        return info;
    }

    const auto pe_offset = read_le32(bytes, 0x3C);
    if (pe_offset + 24 > bytes.size()) {
        return info;
    }
    if (bytes[pe_offset] != 'P' || bytes[pe_offset + 1] != 'E' ||
        bytes[pe_offset + 2] != 0 || bytes[pe_offset + 3] != 0) {
        return info;
    }

    info.valid = true;
    info.pe_offset = pe_offset;
    const auto coff = static_cast<std::size_t>(pe_offset) + 4;
    info.machine = read_le16(bytes, coff);
    info.section_count = read_le16(bytes, coff + 2);
    info.timestamp = read_le32(bytes, coff + 4);
    info.optional_header_size = read_le16(bytes, coff + 16);
    info.characteristics = read_le16(bytes, coff + 18);

    const auto optional = coff + 20;
    if (optional + info.optional_header_size > bytes.size()) {
        throw std::runtime_error("PE optional header extends beyond file size");
    }

    info.magic = read_le16(bytes, optional);
    info.entry_point = read_le32(bytes, optional + 16);
    if (info.magic == 0x20B) {
        info.image_base = read_le64(bytes, optional + 24);
    } else {
        info.image_base = read_le32(bytes, optional + 28);
    }
    info.section_alignment = read_le32(bytes, optional + 32);
    info.file_alignment = read_le32(bytes, optional + 36);

    const auto section_table = optional + info.optional_header_size;
    for (std::uint16_t i = 0; i < info.section_count; ++i) {
        const auto offset = section_table + static_cast<std::size_t>(i) * 40;
        if (offset + 40 > bytes.size()) {
            throw std::runtime_error("PE section table extends beyond file size");
        }

        PeSection section;
        section.name = read_section_name(bytes, offset);
        section.virtual_size = read_le32(bytes, offset + 8);
        section.virtual_address = read_le32(bytes, offset + 12);
        section.raw_size = read_le32(bytes, offset + 16);
        section.raw_pointer = read_le32(bytes, offset + 20);
        section.characteristics = read_le32(bytes, offset + 36);
        info.sections.push_back(section);
    }

    return info;
}

std::string describe_machine(std::uint16_t machine) {
    switch (machine) {
    case 0x014C:
        return "Intel 386";
    case 0x8664:
        return "x64";
    case 0x01C0:
        return "ARM";
    case 0xAA64:
        return "ARM64";
    default:
        return "Unknown";
    }
}
