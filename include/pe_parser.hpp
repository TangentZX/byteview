#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct PeSection {
    std::string name;
    std::uint32_t virtual_size{};
    std::uint32_t virtual_address{};
    std::uint32_t raw_size{};
    std::uint32_t raw_pointer{};
    std::uint32_t characteristics{};
};

struct PeInfo {
    bool valid{};
    std::uint32_t pe_offset{};
    std::uint16_t machine{};
    std::uint16_t section_count{};
    std::uint32_t timestamp{};
    std::uint16_t optional_header_size{};
    std::uint16_t characteristics{};
    std::uint16_t magic{};
    std::uint32_t entry_point{};
    std::uint64_t image_base{};
    std::uint32_t section_alignment{};
    std::uint32_t file_alignment{};
    std::vector<PeSection> sections;
};

PeInfo parse_pe(const std::vector<std::uint8_t>& bytes);
std::string describe_machine(std::uint16_t machine);
