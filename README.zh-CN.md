# ByteView

ByteView 是一个使用 C++17 编写的轻量级二进制文件分析工具，目标是实现一部分 010Editor 风格的底层能力：查看原始字节、识别文件格式、提取字符串、搜索字节序列、转换常见编码，并逐步加入类似模板解析的文件结构分析。

它不是完整替代 010Editor，而是一个适合学习和扩展的 C++ 工程：代码结构清晰，功能模块独立，后续可以继续加入 PE、PNG、ZIP、ELF、CTF 自定义格式等解析器。

## 功能

- 十六进制视图，包含偏移地址和 ASCII 预览
- 常见文件签名识别
- 文件后缀与文件头一致性检测
- 可打印字符串提取
- 十六进制字节序列搜索
- 字符串编码与解码，支持 UTF-8、UTF-16LE、Base64、URL 编码、C 风格转义、hex 和 decimal bytes
- Shannon 熵值计算
- PNG chunk 结构解析
- PE 文件头与 section table 解析
- CMake 组织的 C++17 工程结构

## 使用示例

```powershell
.\byteview.exe info .\samples\readme.txt
.\byteview.exe check .\samples\minimal.png
.\byteview.exe hexdump .\samples\readme.txt 0 128
.\byteview.exe strings .\samples\readme.txt 4
.\byteview.exe search .\samples\readme.txt "42 56 44 45 4D 4F"
.\byteview.exe entropy .\samples\readme.txt
.\byteview.exe pe .\byteview.exe
.\byteview.exe png image.png
.\byteview.exe encode "hello admin"
.\byteview.exe decode base64 "aGVsbG8gYWRtaW4="
.\byteview.exe decode url "hello%20admin"
.\byteview.exe decode hex "68 65 6C 6C 6F"
```

如果要在 Windows 终端中测试中文字符串，建议先切换到 UTF-8 代码页：

```powershell
chcp 65001
.\byteview.exe encode "漏洞"
```

## 命令

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

`decode` 支持的类型：

```text
hex
base64 / b64
url / urlencoded
c / escape / c-escape
decimal / dec
utf16le-hex / utf-16le-hex
```

## 设计思路

010Editor 的核心优势之一是“按结构解释二进制数据”。ByteView 先从更底层的部分做起：读取字节、展示字节、识别魔数、搜索模式、提取字符串、转换常见编码和计算熵值。

在此基础上，`check`、`png` 和 `pe` 命令开始承担更接近“分析器”的角色：

- `check` 会比较文件后缀和文件头魔数，发现 `.jpg` 伪装成 `.png` 这类不一致情况。
- `png` 会读取 PNG 签名，并按顺序解析 chunk 的偏移、类型、长度和 CRC。
- `pe` 会解析 DOS 头中的 PE 偏移、COFF 文件头、Optional Header 关键字段，以及 section table。
- `encode` / `decode` 会在字符串和常见编码之间转换，适合做 payload、协议字段或二进制样本分析时快速查看字节。

这些能力可以继续扩展成更完整的文件格式分析器，也可以用于 CTF Misc、逆向入门、恶意样本初筛和自定义格式调试。

## 后续计划

- 增加 JSON 输出，方便脚本和自动化流程调用
- 增加彩色终端输出
- 增加书签和区间注释
- 增加二进制 diff 模式
- 增加 ZIP 中央目录解析
- 增强 PE import/export 解析

## 构建

使用 CMake：

```powershell
cmake -S . -B build -G "MinGW Makefiles"
cmake --build build
```

也可以直接用 MinGW 编译：

```powershell
g++ -std=c++17 -Wall -Wextra -pedantic -Iinclude src/main.cpp src/analyzer.cpp src/encoder.cpp src/file_reader.cpp src/hex_dump.cpp src/pe_parser.cpp src/png_parser.cpp src/signature.cpp src/strings.cpp src/type_check.cpp -o byteview.exe
```

