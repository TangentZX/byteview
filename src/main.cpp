#include "analyzer.hpp"
#include "encoder.hpp"
#include "file_reader.hpp"
#include "hex_dump.hpp"
#include "pe_parser.hpp"
#include "png_parser.hpp"
#include "signature.hpp"
#include "strings.hpp"
#include "type_check.hpp"

#include <filesystem>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

void print_usage() {
    std::cout
        << "byteview - lightweight binary inspection tool\n\n"
        << "Usage:\n"
        << "  byteview encode <text>\n"
        << "  byteview decode <type> <value>\n"
        << "  byteview info <file>\n"
        << "  byteview check <file>\n"
        << "  byteview hexdump <file> [offset] [length]\n"
        << "  byteview strings <file> [min_length]\n"
        << "  byteview search <file> <hex_pattern>\n"
        << "  byteview entropy <file>\n\n"
        << "  byteview png <file>\n"
        << "  byteview pe <file>\n\n"
        << "Examples:\n"
        << "  byteview hexdump sample.bin 0 128\n"
        << "  byteview search sample.bin \"50 4B 03 04\"\n"
        << "  byteview decode base64 \"aGVsbG8=\"\n";
}

std::size_t parse_size_arg(const char* value) {
    return static_cast<std::size_t>(std::stoull(value, nullptr, 0));
}

std::string collect_text_arg(int start, int argc, char* argv[]) {
    std::string text;
    for (int i = start; i < argc; ++i) {
        if (!text.empty()) {
            text += ' ';
        }
        text += argv[i];
    }
    return text;
}

void print_info(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes) {
    const auto signature = detect_signature(bytes);
    const auto type_check = check_extension_signature(path, signature);
    std::cout << "Path: " << path.string() << '\n';
    std::cout << "Size: " << bytes.size() << " bytes\n";
    std::cout << "Type: " << signature.type << '\n';
    std::cout << "Description: " << signature.description << '\n';
    std::cout << "Extension check: " << type_check.message << '\n';
    std::cout << "Entropy: " << std::fixed << std::setprecision(4)
              << shannon_entropy(bytes) << " bits/byte\n";
}

void print_type_check(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes) {
    const auto signature = detect_signature(bytes);
    const auto result = check_extension_signature(path, signature);
    std::cout << "Extension: " << (result.extension.empty() ? "(none)" : result.extension) << '\n';
    std::cout << "Detected type: " << result.detected_type << '\n';
    std::cout << "Known extension: " << (result.known_extension ? "yes" : "no") << '\n';
    std::cout << "Matched: " << (result.matched ? "yes" : "no") << '\n';
    std::cout << "Result: " << result.message << '\n';
}

void print_encoded_text(const std::string& text) {
    const auto encoded = encode_text(text);
    std::cout << "Input: " << encoded.input << '\n';
    std::cout << "UTF-8 hex: " << encoded.utf8_hex << '\n';
    std::cout << "UTF-16LE hex: " << encoded.utf16le_hex << '\n';
    std::cout << "Decimal bytes: " << encoded.decimal_bytes << '\n';
    std::cout << "Base64: " << encoded.base64 << '\n';
    std::cout << "URL encoded: " << encoded.url_encoded << '\n';
    std::cout << "C escaped: " << encoded.c_escaped << '\n';
}

void print_decoded_text(const std::string& type, const std::string& value) {
    const auto decoded = decode_text(type, value);
    std::cout << "Type: " << decoded.type << '\n';
    std::cout << "Text: " << decoded.text << '\n';
    std::cout << "UTF-8 hex: " << decoded.utf8_hex << '\n';
    std::cout << "Decimal bytes: " << decoded.decimal_bytes << '\n';
    std::cout << "C escaped: " << decoded.c_escaped << '\n';
}

void print_png_info(const std::vector<std::uint8_t>& bytes) {
    const auto png = parse_png(bytes);
    if (!png.valid) {
        std::cout << "Not a PNG file.\n";
        return;
    }

    std::cout << "PNG chunks: " << png.chunks.size() << '\n';
    std::cout << "Offset    Type  Length      CRC\n";
    for (const auto& chunk : png.chunks) {
        std::cout << "0x" << std::hex << std::setw(6) << std::setfill('0') << chunk.offset
                  << "  " << chunk.type
                  << "  " << std::dec << std::setw(10) << std::setfill(' ') << chunk.length
                  << "  0x" << std::hex << std::setw(8) << std::setfill('0') << chunk.crc
                  << std::dec << std::setfill(' ') << '\n';
    }
}

void print_pe_info(const std::vector<std::uint8_t>& bytes) {
    const auto pe = parse_pe(bytes);
    if (!pe.valid) {
        std::cout << "Not a PE file.\n";
        return;
    }

    std::cout << "PE offset: 0x" << std::hex << pe.pe_offset << std::dec << '\n';
    std::cout << "Machine: 0x" << std::hex << pe.machine << std::dec
              << " (" << describe_machine(pe.machine) << ")\n";
    std::cout << "Sections: " << pe.section_count << '\n';
    std::cout << "Timestamp: 0x" << std::hex << pe.timestamp << std::dec << '\n';
    std::cout << "Characteristics: 0x" << std::hex << pe.characteristics << std::dec << '\n';
    std::cout << "Optional magic: 0x" << std::hex << pe.magic << std::dec
              << (pe.magic == 0x20B ? " (PE32+)\n" : " (PE32)\n");
    std::cout << "Entry point RVA: 0x" << std::hex << pe.entry_point << '\n';
    std::cout << "Image base: 0x" << pe.image_base << '\n';
    std::cout << "Section alignment: 0x" << pe.section_alignment << '\n';
    std::cout << "File alignment: 0x" << pe.file_alignment << std::dec << "\n\n";

    std::cout << "Sections\n";
    std::cout << "Name      RVA        VSZ        RawPtr     RawSize    Flags\n";
    for (const auto& section : pe.sections) {
        std::cout << std::left << std::setw(9) << section.name << std::right
                  << " 0x" << std::hex << std::setw(8) << std::setfill('0') << section.virtual_address
                  << " 0x" << std::setw(8) << section.virtual_size
                  << " 0x" << std::setw(8) << section.raw_pointer
                  << " 0x" << std::setw(8) << section.raw_size
                  << " 0x" << std::setw(8) << section.characteristics
                  << std::dec << std::setfill(' ') << '\n';
    }
}

} // namespace

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage();
        return 1;
    }

    const std::string command = argv[1];

    if (command == "encode") {
        if (argc < 3) {
            std::cerr << "Missing text.\n";
            return 1;
        }
        print_encoded_text(collect_text_arg(2, argc, argv));
        return 0;
    }

    if (command == "decode") {
        if (argc < 4) {
            std::cerr << "Usage: byteview decode <type> <value>\n";
            return 1;
        }
        try {
            print_decoded_text(argv[2], collect_text_arg(3, argc, argv));
            return 0;
        } catch (const std::exception& error) {
            std::cerr << "error: " << error.what() << '\n';
            return 1;
        }
    }

    if (argc < 3) {
        print_usage();
        return 1;
    }

    const std::filesystem::path path = argv[2];

    try {
        const auto bytes = read_binary_file(path);

        if (command == "info") {
            print_info(path, bytes);
            return 0;
        }

        if (command == "check") {
            print_type_check(path, bytes);
            return 0;
        }

        if (command == "hexdump") {
            const auto offset = argc >= 4 ? parse_size_arg(argv[3]) : 0;
            const auto length = argc >= 5 ? parse_size_arg(argv[4]) : 256;
            print_hex_dump(bytes, std::cout, offset, length);
            return 0;
        }

        if (command == "strings") {
            const auto min_length = argc >= 4 ? parse_size_arg(argv[3]) : 4;
            for (const auto& item : extract_ascii_strings(bytes, min_length)) {
                std::cout << std::hex << std::setw(8) << std::setfill('0') << item.offset
                          << std::dec << std::setfill(' ') << "  " << item.value << '\n';
            }
            return 0;
        }

        if (command == "search") {
            if (argc < 4) {
                std::cerr << "Missing hex pattern.\n";
                return 1;
            }

            const auto pattern = parse_hex_pattern(argv[3]);
            const auto hits = find_pattern(bytes, pattern);
            if (hits.empty()) {
                std::cout << "No matches.\n";
                return 0;
            }

            for (const auto offset : hits) {
                std::cout << "0x" << std::hex << offset << std::dec << '\n';
            }
            return 0;
        }

        if (command == "entropy") {
            std::cout << std::fixed << std::setprecision(4)
                      << shannon_entropy(bytes) << " bits/byte\n";
            return 0;
        }

        if (command == "png") {
            print_png_info(bytes);
            return 0;
        }

        if (command == "pe") {
            print_pe_info(bytes);
            return 0;
        }

        std::cerr << "Unknown command: " << command << '\n';
        print_usage();
        return 1;
    } catch (const std::exception& error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}
