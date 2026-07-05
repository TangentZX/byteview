cmake_minimum_required(VERSION 3.16)

project(byteview VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(byteview_core
    src/analyzer.cpp
    src/encoder.cpp
    src/file_reader.cpp
    src/hex_dump.cpp
    src/pe_parser.cpp
    src/png_parser.cpp
    src/signature.cpp
    src/strings.cpp
    src/type_check.cpp
)

target_include_directories(byteview_core PUBLIC include)

add_executable(byteview src/main.cpp)
target_link_libraries(byteview PRIVATE byteview_core)

if (MSVC)
    target_compile_options(byteview_core PRIVATE /W4)
    target_compile_options(byteview PRIVATE /W4)
else()
    target_compile_options(byteview_core PRIVATE -Wall -Wextra -pedantic)
    target_compile_options(byteview PRIVATE -Wall -Wextra -pedantic)
endif()
