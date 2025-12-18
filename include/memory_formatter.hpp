#pragma once

#include "types.hpp"

namespace mcp_server_pcileech {

class MemoryFormatter {
public:
    static string format_hex_dump(const MemoryData& data, const string& address, bool show_ascii = true);

    struct MemoryViews {
        string hex_dump;
        string ascii_view;
        string byte_array;
        string dword_array;
        string raw_hex;
    };

    static MemoryViews format_all_views(const MemoryData& data, const string& address);

    static string format_byte_array(const MemoryData& data);
    static string format_dword_array(const MemoryData& data);
    static string format_ascii_view(const MemoryData& data);

private:
    static constexpr size_t BYTES_PER_LINE = 16;
    static constexpr size_t HEX_DUMP_WIDTH = 47;
    static constexpr size_t ASCII_WIDTH = 16;

    static string format_hex_line(uint64_t addr, const uint8_t* data, size_t length, bool show_ascii);
    static string format_ascii_chars(const uint8_t* data, size_t length);
    static string pad_hex_string(const string& hex_str);
};

}
