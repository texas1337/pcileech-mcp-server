#include "memory_formatter.hpp"
#include "utils.hpp"
#include <iomanip>
#include <sstream>
#include <algorithm>

namespace mcp_server_pcileech {

string MemoryFormatter::format_hex_dump(const MemoryData& data, const string& address, bool show_ascii) {
    std::ostringstream oss;
    uint64_t addr_int = utils::hex_to_uint64(address);

    for (size_t i = 0; i < data.size(); i += BYTES_PER_LINE) {
        size_t chunk_size = std::min(BYTES_PER_LINE, data.size() - i);
        const uint8_t* chunk = data.data() + i;
        oss << format_hex_line(addr_int + i, chunk, chunk_size, show_ascii) << '\n';
    }

    return oss.str();
}

string MemoryFormatter::format_hex_line(uint64_t addr, const uint8_t* data, size_t length, bool show_ascii) {
    std::ostringstream oss;

    oss << "0x" << std::hex << std::setw(16) << std::setfill('0') << addr << ": ";

    for (size_t i = 0; i < BYTES_PER_LINE; ++i) {
        if (i < length) {
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
        } else {
            oss << "  ";
        }

        if (i % 8 == 7 && i < BYTES_PER_LINE - 1) {
            oss << " ";
        } else if (i < BYTES_PER_LINE - 1) {
            oss << " ";
        }
    }

    if (show_ascii) {
        oss << "  |" << format_ascii_chars(data, length) << "|";
    }

    return oss.str();
}

string MemoryFormatter::format_ascii_chars(const uint8_t* data, size_t length) {
    std::string result;
    for (size_t i = 0; i < BYTES_PER_LINE; ++i) {
        if (i < length) {
            char c = static_cast<char>(data[i]);
            result += (c >= 32 && c < 127) ? c : '.';
        } else {
            result += ' ';
        }
    }
    return result;
}

string MemoryFormatter::format_byte_array(const MemoryData& data) {
    std::ostringstream oss;
    oss << '[';
    for (size_t i = 0; i < data.size(); ++i) {
        if (i > 0) oss << ", ";
        oss << static_cast<int>(data[i]);
    }
    oss << ']';
    return oss.str();
}

string MemoryFormatter::format_dword_array(const MemoryData& data) {
    std::vector<string> dwords;
    for (size_t i = 0; i + 3 < data.size(); i += 4) {
        uint32_t dword = *reinterpret_cast<const uint32_t*>(&data[i]);
        std::ostringstream oss;
        oss << "0x" << std::hex << std::setw(8) << std::setfill('0') << dword;
        dwords.push_back(oss.str());
    }
    return '[' + utils::join(dwords, ", ") + ']';
}

string MemoryFormatter::format_ascii_view(const MemoryData& data) {
    string result;
    for (uint8_t byte : data) {
        char c = static_cast<char>(byte);
        result += (c >= 32 && c < 127) ? c : '.';
    }
    return result;
}

MemoryFormatter::MemoryViews MemoryFormatter::format_all_views(const MemoryData& data, const string& address) {
    return {
        format_hex_dump(data, address, true),
        format_ascii_view(data),
        format_byte_array(data),
        format_dword_array(data),
        utils::bytes_to_hex(data)
    };
}

}
