# ByteView

ByteView is a small C++17 command line tool for inspecting binary files.

It is not a full 010Editor replacement yet. The goal is to build a compact, hackable core: file loading, hex view, file signature detection, byte search, string extraction, and entropy analysis. Those are the building blocks behind many binary inspection workflows.

## Features

- Hex dump with offset and ASCII preview
- File signature detection for common formats
- Extension and file signature consistency check
- ASCII string extraction
- Hex pattern search
- Text encode/decode helper for UTF-8, UTF-16LE, Base64, URL encoding, C escapes, hex, and decimal bytes
- Shannon entropy calculation
- PNG chunk parsing
- PE header and section table parsing
- CMake-based C++17 project structure

## Build

```powershell
cmake -S . -B build -G "MinGW Makefiles"
cmake --build build
```

You can also build directly with MinGW:

```powershell
g++ -std=c++17 -Wall -Wextra -pedantic -Iinclude src/main.cpp src/analyzer.cpp src/encoder.cpp src/file_reader.cpp src/hex_dump.cpp src/pe_parser.cpp src/png_parser.cpp src/signature.cpp src/strings.cpp src/type_check.cpp -o byteview.exe
```

## Usage

```powershell
.\build\byteview.exe info .\samples\readme.txt
.\build\byteview.exe check .\samples\minimal.png
.\build\byteview.exe hexdump .\samples\readme.txt 0 128
.\build\byteview.exe strings .\samples\readme.txt 4
.\build\byteview.exe search .\samples\readme.txt "42 56 44 45 4D 4F"
.\build\byteview.exe entropy .\samples\readme.txt
.\build\byteview.exe pe .\build\byteview.exe
.\build\byteview.exe png image.png
.\build\byteview.exe encode "hello admin"
.\build\byteview.exe decode base64 "aGVsbG8gYWRtaW4="
.\build\byteview.exe decode url "hello%20admin"
.\build\byteview.exe decode hex "68 65 6C 6C 6F"
```

For non-ASCII input on Windows, switch the console to UTF-8 first:

```powershell
chcp 65001
.\build\byteview.exe encode "漏洞"
```

## Commands

```text
byteview encode <text>
byteview decode <type> <value>
byteview info <file>
byteview check <file>
byteview hexdump <file> [offset] [length]
byteview strings <file> [min_length]
byteview search <file> <hex_pattern>
byteview entropy <file>
byteview png <file>
byteview pe <file>
```

Supported decode types:

```text
hex
base64 / b64
url / urlencoded
c / escape / c-escape
decimal / dec
utf16le-hex / utf-16le-hex
```

## Why This Project

010Editor is powerful because it combines binary viewing with structure templates. ByteView starts from the lower layer: reading raw bytes, showing them reliably, detecting signatures, checking suspicious file extensions, converting common encodings, and extracting useful signals. The `png` and `pe` commands are the first steps toward template-style parsing.

## Roadmap

- Add JSON output for automation
- Add colored terminal output
- Add bookmarks and region comments
- Add binary diff mode
- Add ZIP central directory parser
- Add richer PE import/export parsing
