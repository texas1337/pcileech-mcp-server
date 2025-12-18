#include "utils.hpp"
#include <windows.h>
#include <shlwapi.h>
#include <algorithm>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <regex>
#include <thread>
#include <fstream>
#include <filesystem>

#pragma comment(lib, "shlwapi.lib")

namespace mcp_server_pcileech {
namespace utils {

string to_lower(const string& str) {
    string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

string to_upper(const string& str) {
    string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::toupper);
    return result;
}

string trim(const string& str) {
    auto start = str.begin();
    while (start != str.end() && std::isspace(*start)) ++start;

    auto end = str.end();
    do {
        --end;
    } while (std::distance(start, end) > 0 && std::isspace(*end));

    return string(start, end + 1);
}

string ltrim(const string& str) {
    auto it = str.begin();
    while (it != str.end() && std::isspace(*it)) ++it;
    return string(it, str.end());
}

string rtrim(const string& str) {
    auto it = str.rbegin();
    while (it != str.rend() && std::isspace(*it)) ++it;
    return string(str.begin(), it.base());
}

std::vector<string> split(const string& str, char delimiter) {
    std::vector<string> tokens;
    string token;
    std::istringstream tokenStream(str);
    while (std::getline(tokenStream, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
}

std::vector<string> split_lines(const string& str) {
    return split(str, '\n');
}

string join(const std::vector<string>& vec, const string& delimiter) {
    if (vec.empty()) return "";
    string result = vec[0];
    for (size_t i = 1; i < vec.size(); ++i) {
        result += delimiter + vec[i];
    }
    return result;
}

string bytes_to_hex(const MemoryData& data) {
    std::ostringstream oss;
    for (uint8_t byte : data) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return oss.str();
}

MemoryData hex_to_bytes(const string& hex_str) {
    MemoryData result;
    for (size_t i = 0; i < hex_str.length(); i += 2) {
        string byte_str = hex_str.substr(i, 2);
        result.push_back(static_cast<uint8_t>(std::stoi(byte_str, nullptr, 16)));
    }
    return result;
}

bool is_valid_hex(const string& str, bool allow_prefix) {
    if (str.empty()) return false;
    string s = str;
    if (allow_prefix && s.substr(0, 2) == "0x") {
        s = s.substr(2);
    }
    return std::all_of(s.begin(), s.end(), ::isxdigit) && (s.length() % 2 == 0);
}

uint64_t hex_to_uint64(const string& hex_str) {
    string s = hex_str;
    if (s.substr(0, 2) == "0x") {
        s = s.substr(2);
    }
    return std::stoull(s, nullptr, 16);
}

string uint64_to_hex(uint64_t value, bool prefix, int width) {
    std::ostringstream oss;
    if (prefix) oss << "0x";
    oss << std::hex << std::setw(width) << std::setfill('0') << value;
    return oss.str();
}

string sanitize_path_component(const string& component, const string& param_name) {
    if (component.empty() || trim(component).empty()) {
        throw PCILeechError(param_name + " cannot be empty");
    }

    string name = trim(component);
    if (name.find("..") != string::npos || name.find("/") != string::npos ||
        name.find("\\") != string::npos) {
        throw PCILeechError(param_name + " cannot contain path separators or '..': " + name);
    }

    if (PathIsRelativeA(name.c_str()) == FALSE) {
        throw PCILeechError(param_name + " cannot be an absolute path: " + name);
    }

    return name;
}

bool path_exists(const string& path) {
    return std::filesystem::exists(path);
}

string get_current_executable_path() {
    std::wstring exe_path_w;
    DWORD size = MAX_PATH;

    for (;;) {
        exe_path_w.assign(size, L'\0');
        DWORD len = GetModuleFileNameW(nullptr, exe_path_w.data(), size);
        if (len == 0) {
            DWORD error_code = GetLastError();
            throw PCILeechError("GetModuleFileNameW failed (error " + std::to_string(error_code) + ")");
        }

        if (len < size - 1) {
            exe_path_w.resize(len);
            break;
        }

        if (size > 32768) {
            throw PCILeechError("Executable path too long");
        }
        size *= 2;
    }

    int utf8_len = WideCharToMultiByte(CP_UTF8, 0, exe_path_w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (utf8_len <= 0) {
        DWORD error_code = GetLastError();
        throw PCILeechError("WideCharToMultiByte failed (error " + std::to_string(error_code) + ")");
    }

    std::string exe_utf8(static_cast<size_t>(utf8_len), '\0');
    if (WideCharToMultiByte(CP_UTF8, 0, exe_path_w.c_str(), -1, exe_utf8.data(), utf8_len, nullptr, nullptr) == 0) {
        DWORD error_code = GetLastError();
        throw PCILeechError("WideCharToMultiByte failed (error " + std::to_string(error_code) + ")");
    }

    if (!exe_utf8.empty() && exe_utf8.back() == '\0') {
        exe_utf8.pop_back();
    }

    return exe_utf8;
}

string get_executable_directory() {
    string exe_path_utf8 = get_current_executable_path();

    std::filesystem::path p(exe_path_utf8);
    return p.parent_path().string();
}

string combine_paths(const string& path1, const string& path2) {
    return (std::filesystem::path(path1) / path2).string();
}

uint64_t parse_hex_address(const string& value, const string& name) {
    if (value.empty()) {
        throw PCILeechError(name + " cannot be empty");
    }

    string s = trim(to_lower(value));
    if (s.substr(0, 2) == "0x") {
        s = s.substr(2);
    }

    if (s.empty() || !std::all_of(s.begin(), s.end(), ::isxdigit)) {
        throw PCILeechError("Invalid " + name + " format '" + value + "' (expected hex like 0x1000)");
    }

    try {
        uint64_t n = std::stoull(s, nullptr, 16);
        if (n > UINT64_MAX) {
            throw PCILeechError(name + " exceeds 64-bit range: " + value);
        }
        return n;
    } catch (const std::exception&) {
        throw PCILeechError("Invalid " + name + " format '" + value + "'");
    }
}

void validate_address_range(uint64_t address, size_t length, const string& param_prefix) {
    if (length == 0) {
        throw PCILeechError(param_prefix + "length must be positive, got " + std::to_string(length));
    }

    uint64_t end_address = address + length - 1;
    if (end_address > UINT64_MAX) {
        throw PCILeechError("Address range overflow: 0x" + uint64_to_hex(address) +
                          " + " + std::to_string(length) + " bytes exceeds 64-bit address space");
    }
}

void validate_length(size_t length, size_t min_val, size_t max_val) {
    if (length < min_val) {
        throw PCILeechError("length must be >= " + std::to_string(min_val) +
                          ", got " + std::to_string(length));
    }
    if (max_val > 0 && length > max_val) {
        throw PCILeechError("length must be <= " + std::to_string(max_val) +
                          ", got " + std::to_string(length));
    }
}

bool validate_hex_data(const string& hex_string, const string& param_name) {
    if (hex_string.empty()) {
        throw PCILeechError(param_name + " cannot be empty");
    }

    if (hex_string.length() % 2 != 0) {
        throw PCILeechError(param_name + " has odd length (" + std::to_string(hex_string.length()) +
                          "). Hex strings must have even length (2 chars per byte)");
    }

    if (!std::all_of(hex_string.begin(), hex_string.end(), ::isxdigit)) {
        throw PCILeechError(param_name + " contains invalid hex characters");
    }

    return true;
}

string validate_process_name(const string& name) {
    if (name.empty() || trim(name).empty()) {
        throw PCILeechError("process_name cannot be empty");
    }

    string trimmed = trim(name);

    if (trimmed.length() > 260) {
        throw PCILeechError("process_name too long: " + std::to_string(trimmed.length()) +
                          " chars (max 260)");
    }

    if (!std::all_of(trimmed.begin(), trimmed.end(), [](char c) {
        return std::isalnum(c) || c == '.' || c == '_' || c == '-' || c == ' ';
    })) {
        throw PCILeechError("process_name contains invalid characters: '" + trimmed +
                          "'. Only alphanumeric, dot, underscore, hyphen, and space allowed");
    }

    return trimmed;
}

bool is_valid_process_name(const string& name) {
    try {
        validate_process_name(name);
        return true;
    } catch (...) {
        return false;
    }
}

CommandResult execute_command(const std::vector<string>& args, int timeout_seconds) {
    return execute_command(args, timeout_seconds, std::nullopt);
}

CommandResult execute_command(const std::vector<string>& args, int timeout_seconds, std::optional<string> working_directory) {
    if (args.empty()) {
        throw ValidationError("No command arguments provided");
    }

    if (timeout_seconds < 0) {
        throw ValidationError("Invalid timeout: " + std::to_string(timeout_seconds));
    }

    std::string command_line;
    for (size_t i = 0; i < args.size(); ++i) {
        if (i > 0) command_line += " ";
        if (args[i].find(' ') != string::npos) {
            command_line += "\"" + args[i] + "\"";
        } else {
            command_line += args[i];
        }
    }

    int wide_len = MultiByteToWideChar(CP_UTF8, 0, command_line.c_str(), -1, nullptr, 0);
    if (wide_len <= 0) {
        DWORD error_code = GetLastError();
        throw PCILeechError("Failed to convert command to wide string (error " + std::to_string(error_code) + ")");
    }

    std::wstring wide_command_line(static_cast<size_t>(wide_len), L'\0');
    if (MultiByteToWideChar(CP_UTF8, 0, command_line.c_str(), -1, wide_command_line.data(), wide_len) == 0) {
        DWORD error_code = GetLastError();
        throw PCILeechError("Failed to convert command to wide string (error " + std::to_string(error_code) + ")");
    }

    std::wstring wide_working_dir;
    LPCWSTR working_dir_ptr = nullptr;
    if (working_directory && !working_directory->empty()) {
        int wd_len = MultiByteToWideChar(CP_UTF8, 0, working_directory->c_str(), -1, nullptr, 0);
        if (wd_len <= 0) {
            DWORD error_code = GetLastError();
            throw PCILeechError("Failed to convert working directory to wide string (error " + std::to_string(error_code) + ")");
        }

        wide_working_dir.assign(static_cast<size_t>(wd_len), L'\0');
        if (MultiByteToWideChar(CP_UTF8, 0, working_directory->c_str(), -1, wide_working_dir.data(), wd_len) == 0) {
            DWORD error_code = GetLastError();
            throw PCILeechError("Failed to convert working directory to wide string (error " + std::to_string(error_code) + ")");
        }

        working_dir_ptr = wide_working_dir.c_str();
    }

    struct HandleCloser {
        void operator()(HANDLE h) const noexcept {
            if (h && h != INVALID_HANDLE_VALUE) {
                CloseHandle(h);
            }
        }
    };
    using unique_handle = std::unique_ptr<void, HandleCloser>;

    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = nullptr;
    sa.bInheritHandle = TRUE;

    HANDLE out_read_raw = nullptr;
    HANDLE out_write_raw = nullptr;
    if (!CreatePipe(&out_read_raw, &out_write_raw, &sa, 0)) {
        DWORD error_code = GetLastError();
        throw PCILeechError("CreatePipe(stdout) failed (error " + std::to_string(error_code) + ")");
    }
    if (!SetHandleInformation(out_read_raw, HANDLE_FLAG_INHERIT, 0)) {
        DWORD error_code = GetLastError();
        CloseHandle(out_read_raw);
        CloseHandle(out_write_raw);
        throw PCILeechError("SetHandleInformation(stdout) failed (error " + std::to_string(error_code) + ")");
    }

    HANDLE err_read_raw = nullptr;
    HANDLE err_write_raw = nullptr;
    if (!CreatePipe(&err_read_raw, &err_write_raw, &sa, 0)) {
        DWORD error_code = GetLastError();
        CloseHandle(out_read_raw);
        CloseHandle(out_write_raw);
        throw PCILeechError("CreatePipe(stderr) failed (error " + std::to_string(error_code) + ")");
    }
    if (!SetHandleInformation(err_read_raw, HANDLE_FLAG_INHERIT, 0)) {
        DWORD error_code = GetLastError();
        CloseHandle(out_read_raw);
        CloseHandle(out_write_raw);
        CloseHandle(err_read_raw);
        CloseHandle(err_write_raw);
        throw PCILeechError("SetHandleInformation(stderr) failed (error " + std::to_string(error_code) + ")");
    }

    unique_handle out_read(out_read_raw);
    unique_handle out_write(out_write_raw);
    unique_handle err_read(err_read_raw);
    unique_handle err_write(err_write_raw);

    unique_handle null_in(CreateFileW(L"NUL", GENERIC_READ,
                                     FILE_SHARE_READ | FILE_SHARE_WRITE,
                                     &sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (static_cast<HANDLE>(null_in.get()) == INVALID_HANDLE_VALUE) {
        DWORD error_code = GetLastError();
        throw PCILeechError("CreateFileW(NUL) failed (error " + std::to_string(error_code) + ")");
    }

    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = static_cast<HANDLE>(null_in.get());
    si.hStdOutput = static_cast<HANDLE>(out_write.get());
    si.hStdError = static_cast<HANDLE>(err_write.get());

    PROCESS_INFORMATION pi = {};

    auto start_time = std::chrono::steady_clock::now();

    if (!CreateProcessW(nullptr, &wide_command_line[0], nullptr, nullptr, TRUE,
                        CREATE_NO_WINDOW, nullptr, working_dir_ptr, &si, &pi)) {
        DWORD error_code = GetLastError();
        throw PCILeechError("Failed to create process '" + args[0] + "' (error " + std::to_string(error_code) + ")");
    }

    unique_handle process_handle(pi.hProcess);
    unique_handle thread_handle(pi.hThread);

    out_write.reset();
    err_write.reset();
    null_in.reset();

    std::string stdout_data;
    std::string stderr_data;

    auto read_pipe = [](unique_handle h, std::string* dst) {
        HANDLE pipe = static_cast<HANDLE>(h.get());
        char buffer[4096];
        DWORD bytes_read = 0;
        while (true) {
            BOOL ok = ReadFile(pipe, buffer, static_cast<DWORD>(sizeof(buffer)), &bytes_read, nullptr);
            if (!ok || bytes_read == 0) {
                break;
            }
            dst->append(buffer, bytes_read);
        }
    };

    std::thread stdout_thread(read_pipe, std::move(out_read), &stdout_data);
    std::thread stderr_thread(read_pipe, std::move(err_read), &stderr_data);

    bool did_timeout = false;
    DWORD wait_ms = timeout_seconds > 0 ? static_cast<DWORD>(timeout_seconds) * 1000 : INFINITE;
    DWORD wait_result = WaitForSingleObject(static_cast<HANDLE>(process_handle.get()), wait_ms);

    if (wait_result == WAIT_TIMEOUT) {
        did_timeout = true;
        TerminateProcess(static_cast<HANDLE>(process_handle.get()), 1);
        WaitForSingleObject(static_cast<HANDLE>(process_handle.get()), INFINITE);
    } else if (wait_result != WAIT_OBJECT_0) {
        DWORD error_code = GetLastError();
        TerminateProcess(static_cast<HANDLE>(process_handle.get()), 1);
        WaitForSingleObject(static_cast<HANDLE>(process_handle.get()), INFINITE);
        if (stdout_thread.joinable()) stdout_thread.join();
        if (stderr_thread.joinable()) stderr_thread.join();
        throw PCILeechError("Process wait failed for '" + args[0] + "' (error " + std::to_string(error_code) + ")");
    }

    auto end_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

    CommandResult result;
    result.return_code = -1;
    result.duration = duration;

    if (!GetExitCodeProcess(static_cast<HANDLE>(process_handle.get()), reinterpret_cast<DWORD*>(&result.return_code))) {
        DWORD error_code = GetLastError();
        if (stdout_thread.joinable()) stdout_thread.join();
        if (stderr_thread.joinable()) stderr_thread.join();
        throw PCILeechError("Failed to get exit code for '" + args[0] + "' (error " + std::to_string(error_code) + ")");
    }

    if (stdout_thread.joinable()) stdout_thread.join();
    if (stderr_thread.joinable()) stderr_thread.join();

    result.command_output = stdout_data;
    result.error_output = stderr_data;

    if (did_timeout) {
        throw TimeoutError("Command '" + args[0] + "' timed out after " + std::to_string(timeout_seconds) + " seconds");
    }

    return result;
}

std::optional<std::string> detect_failure(const std::string& command_output, const std::string& error_output) {
    string combined = command_output + "\n" + error_output;

    std::vector<std::regex> patterns = {
        std::regex(R"(Failed reading memory at address:\s*(0x[0-9a-fA-F]+)?)", std::regex_constants::icase),
        std::regex(R"(Failed translating address)", std::regex_constants::icase),
        std::regex(R"(UMD:\s*Failed)", std::regex_constants::icase),
        std::regex(R"(Memory Display:\s*Failed)", std::regex_constants::icase),
        std::regex(R"(\bSYNTAX:\b)", std::regex_constants::icase),
        std::regex(R"(Failed retrieving information)", std::regex_constants::icase)
    };

    for (const auto& pattern : patterns) {
        std::smatch match;
        if (std::regex_search(combined, match, pattern)) {
            return match.str();
        }
    }

    for (const string& line : split_lines(combined)) {
        string lower = to_lower(line);
        if (lower.find("failed") != string::npos && lower.find("success") == string::npos) {
            return trim(line);
        }
    }

    return std::nullopt;
}

Platform detect_platform_from_script_name(const string& script_name) {
    if (script_name.substr(0, 5) == "wx64_") return Platform::Windows;
    if (script_name.substr(0, 5) == "wx86_") return Platform::Windows;
    if (script_name.substr(0, 5) == "lx64_") return Platform::Linux;
    if (script_name.substr(0, 12) == "fbsdx64_") return Platform::FreeBSD;
    if (script_name.substr(0, 5) == "macos_") return Platform::macOS;
    if (script_name.substr(0, 5) == "uefi_") return Platform::UEFI;
    return Platform::Unknown;
}

string platform_to_string(Platform platform) {
    switch (platform) {
        case Platform::Windows: return "windows";
        case Platform::Linux: return "linux";
        case Platform::macOS: return "macos";
        case Platform::FreeBSD: return "freebsd";
        case Platform::UEFI: return "uefi";
        default: return "unknown";
    }
}

std::optional<string> read_file(const string& path) {
    try {
        std::ifstream file(path);
        if (!file.is_open()) return std::nullopt;

        std::stringstream buffer;
        buffer << file.rdbuf();
        return buffer.str();
    } catch (...) {
        return std::nullopt;
    }
}

bool write_file(const string& path, const string& content) {
    try {
        std::ofstream file(path);
        if (!file.is_open()) return false;

        file << content;
        return true;
    } catch (...) {
        return false;
    }
}

string get_current_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    std::tm tm;
    localtime_s(&tm, &time_t);

    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

json parse_json(const string& json_str) {
    return json::parse(json_str);
}

string json_to_string(const json& j, bool pretty) {
    return j.dump(pretty ? 2 : 0);
}

string format_error_message(const string& context, const std::exception& e) {
    return context + ": " + e.what();
}

}
}