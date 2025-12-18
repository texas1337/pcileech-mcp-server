#pragma once

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <unordered_map>
#include <variant>
#include <optional>
#include <memory>
#include <chrono>

namespace mcp_server_pcileech {

class PCILeechWrapper;

using json = nlohmann::json;
using string = std::string;
using string_view = std::string_view;
using JsonValue = json;
using ToolArgs = std::unordered_map<string, JsonValue>;
using MemoryData = std::vector<uint8_t>;

struct ProcessInfo {
    uint32_t pid;
    std::optional<uint32_t> ppid;
    string name;
    json to_json() const;
    static ProcessInfo from_json(const json& j);
};

struct MemoryRegion {
    uint64_t start;
    uint64_t end;
    uint64_t size;
    double size_mb;
    string status;
    json to_json() const;
    static MemoryRegion from_json(const json& j);
};

struct SearchMatch {
    uint64_t address;
    string line;
    json to_json() const;
    static SearchMatch from_json(const json& j);
};

struct SystemInfo {
    std::optional<string> device;
    bool fpga;
    std::optional<string> memory_max;
    string raw_output;
    json to_json() const;
    static SystemInfo from_json(const json& j);
};

struct TranslationResult {
    std::optional<uint64_t> physical;
    uint64_t cr3;
    std::optional<uint64_t> virtual_addr;
    bool success;
    string output;
    std::optional<string> error;
    json to_json() const;
    static TranslationResult from_json(const json& j);
};

struct ProcessTranslationResult {
    uint32_t pid;
    uint64_t virtual_addr;
    std::optional<uint64_t> physical;
    bool success;
    string output;
    std::optional<string> error;
    json to_json() const;
    static ProcessTranslationResult from_json(const json& j);
};

struct KMDLoadResult {
    string kmd_type;
    bool success;
    std::optional<string> kmd_address;
    string output;
    std::optional<string> error;
    json to_json() const;
    static KMDLoadResult from_json(const json& j);
};

struct KMDUnloadResult {
    string kmd_address;
    bool success;
    string output;
    std::optional<string> error;
    json to_json() const;
    static KMDUnloadResult from_json(const json& j);
};

struct KSHExecuteResult {
    string script;
    string kmd_address;
    bool success;
    string output;
    std::optional<string> error;
    json to_json() const;
    static KSHExecuteResult from_json(const json& j);
};

struct KernelScript {
    string name;
    string platform;
    string path;
    json to_json() const;
    static KernelScript from_json(const json& j);
};

struct MemoryDumpResult {
    string min_address;
    string max_address;
    bool success;
    std::optional<string> file;
    string output;
    json to_json() const;
    static MemoryDumpResult from_json(const json& j);
};

struct MemorySearchResult {
    string search_term;
    std::optional<string> min_address;
    std::optional<string> max_address;
    std::vector<SearchMatch> matches;
    json to_json() const;
    static MemorySearchResult from_json(const json& j);
};

struct MemoryPatchResult {
    string signature;
    bool success;
    string output;
    size_t matches_found;
    size_t patches_applied;
    json to_json() const;
    static MemoryPatchResult from_json(const json& j);
};

struct BenchmarkResult {
    string test_type;
    string address;
    bool success;
    string output;
    std::optional<double> speed_mbps;
    json to_json() const;
    static BenchmarkResult from_json(const json& j);
};

struct TLPResult {
    bool success;
    std::optional<string> tlp_sent;
    double wait_seconds;
    string output;
    std::vector<string> tlp_received;
    json to_json() const;
    static TLPResult from_json(const json& j);
};

struct FPGAConfigResult {
    string action;
    std::optional<string> address;
    bool success;
    string output;
    std::optional<string> data;
    json to_json() const;
    static FPGAConfigResult from_json(const json& j);
};

struct Tool {
    string name;
    string description;
    json input_schema;
    json to_json() const;
};

struct TextContent {
    string type = "text";
    string text;
    json to_json() const;
};

struct ToolCall {
    string name;
    ToolArgs arguments;
    json to_json() const;
};

struct ToolResponse {
    std::vector<TextContent> content;
    json to_json() const;
};

enum class ErrorCode {
    SUCCESS = 0,
    CONFIG_ERROR = 1,
    HARDWARE_ERROR = 2,
    MEMORY_ERROR = 3,
    NETWORK_ERROR = 4,
    PERMISSION_ERROR = 5,
    TIMEOUT_ERROR = 6,
    VALIDATION_ERROR = 7,
    UNKNOWN_ERROR = 99
};

class PCILeechError : public std::runtime_error {
public:
    explicit PCILeechError(const string& message, ErrorCode code = ErrorCode::UNKNOWN_ERROR)
        : std::runtime_error(message), error_code_(code) {}

    ErrorCode getErrorCode() const { return error_code_; }

protected:
    ErrorCode error_code_;
};

class ConfigError : public PCILeechError {
public:
    explicit ConfigError(const string& message) : PCILeechError(message, ErrorCode::CONFIG_ERROR) {}
};

class DeviceNotFoundError : public PCILeechError {
public:
    explicit DeviceNotFoundError(const string& message) : PCILeechError(message, ErrorCode::HARDWARE_ERROR) {}
};

class MemoryAccessError : public PCILeechError {
public:
    explicit MemoryAccessError(const string& message) : PCILeechError(message, ErrorCode::MEMORY_ERROR) {}
};

class SignatureNotFoundError : public PCILeechError {
public:
    explicit SignatureNotFoundError(const string& message) : PCILeechError(message, ErrorCode::VALIDATION_ERROR) {}
};

class ProbeNotSupportedError : public PCILeechError {
public:
    explicit ProbeNotSupportedError(const string& message) : PCILeechError(message, ErrorCode::HARDWARE_ERROR) {}
};

class KMDError : public PCILeechError {
public:
    explicit KMDError(const string& message) : PCILeechError(message, ErrorCode::MEMORY_ERROR) {}
};

class TimeoutError : public PCILeechError {
public:
    explicit TimeoutError(const string& message) : PCILeechError(message, ErrorCode::TIMEOUT_ERROR) {}
};

class ValidationError : public PCILeechError {
public:
    explicit ValidationError(const string& message) : PCILeechError(message, ErrorCode::VALIDATION_ERROR) {}
};

json variant_to_json(const JsonValue& value);
JsonValue json_to_variant(const json& j);

}
