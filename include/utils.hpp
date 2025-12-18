#pragma once

#include "types.hpp"
#include <regex>
#include <filesystem>
#include <algorithm>

namespace mcp_server_pcileech {
namespace utils {

string to_lower(const string& str);
string to_upper(const string& str);
string trim(const string& str);
string ltrim(const string& str);
string rtrim(const string& str);
std::vector<string> split(const string& str, char delimiter = ' ');
std::vector<string> split_lines(const string& str);

string bytes_to_hex(const MemoryData& data);
MemoryData hex_to_bytes(const string& hex_str);
bool is_valid_hex(const string& str, bool allow_prefix = true);
uint64_t hex_to_uint64(const string& hex_str);
string uint64_to_hex(uint64_t value, bool prefix = true, int width = 16);

string sanitize_path_component(const string& component, const string& param_name);
bool path_exists(const string& path);
string get_executable_directory();
string get_current_executable_path();
string combine_paths(const string& path1, const string& path2);

uint64_t parse_hex_address(const string& value, const string& name = "address");
void validate_address_range(uint64_t address, size_t length, const string& param_prefix = "");
void validate_length(size_t length, size_t min_val = 1, size_t max_val = 0);
bool validate_hex_data(const string& hex_string, const string& param_name = "data");
string validate_process_name(const string& name);

string format_memory_dump(const MemoryData& data, const string& address, bool show_ascii = true);
string format_byte_array(const MemoryData& data);
string format_dword_array(const MemoryData& data);
string format_ascii_view(const MemoryData& data);

bool is_valid_process_name(const string& name);

struct CommandResult {
    string command_output;
    string error_output;
    int return_code;
    std::chrono::milliseconds duration;
};

CommandResult execute_command(const std::vector<string>& args, int timeout_seconds = 30);
CommandResult execute_command(const std::vector<string>& args,
                             int timeout_seconds,
                             std::optional<string> working_directory);

std::optional<std::string> detect_failure(const std::string& command_output, const std::string& error_output);

enum class Platform {
    Windows,
    Linux,
    macOS,
    FreeBSD,
    UEFI,
    Unknown
};

Platform detect_platform_from_script_name(const string& script_name);
string platform_to_string(Platform platform);

template<typename T>
std::optional<T> string_to_number(const string& str) {
    try {
        if constexpr (std::is_integral_v<T>) {
            if constexpr (std::is_unsigned_v<T>) {
                return static_cast<T>(std::stoull(str));
            } else {
                return static_cast<T>(std::stoll(str));
            }
        } else {
            return static_cast<T>(std::stod(str));
        }
    } catch (...) {
        return std::nullopt;
    }
}

template<typename T>
string number_to_string(T value) {
    if constexpr (std::is_integral_v<T>) {
        return std::to_string(value);
    } else {
        return std::to_string(value);
    }
}

std::vector<string> regex_findall(const string& pattern, const string& text);
std::optional<string> regex_search(const string& pattern, const string& text);
string regex_replace(const string& pattern, const string& replacement, const string& text);

string join(const std::vector<string>& strings, const string& delimiter = " ");

std::optional<string> read_file(const string& path);
bool write_file(const string& path, const string& content);

string get_current_timestamp();

json parse_json(const string& json_str);
string json_to_string(const json& j, bool pretty = false);

string format_error_message(const string& context, const std::exception& e);

}
}
