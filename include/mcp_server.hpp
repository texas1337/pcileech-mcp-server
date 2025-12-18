#pragma once

#include "types.hpp"
#include "pcileech_wrapper.hpp"
#include "config.hpp"
#include <functional>
#include <future>
#include <atomic>

namespace mcp_server_pcileech {

class MCPServer {
public:
    explicit MCPServer(const Config& config);
    ~MCPServer() = default;

    MCPServer(const MCPServer&) = delete;
    MCPServer& operator=(const MCPServer&) = delete;
    MCPServer(MCPServer&&) = delete;
    MCPServer& operator=(MCPServer&&) = delete;
    void run();

private:
    const Config& config_;
    std::unique_ptr<PCILeechWrapper> pcileech_;
    std::atomic<bool> running_;
    mutable std::mutex pcileech_mutex_;
    void handle_message(const json& message);
    void handle_initialize(const json& message);
    void handle_list_tools(const json& message);
    void handle_call_tool(const json& message);
    void handle_shutdown(const json& message);
    void send_response(const json& response);
    void send_error(int code, const string& message, const json& id);
    ToolResponse handle_memory_read(const ToolArgs& args);
    ToolResponse handle_memory_write(const ToolArgs& args);
    ToolResponse handle_memory_format(const ToolArgs& args);
    ToolResponse handle_system_info(const ToolArgs& args);
    ToolResponse handle_memory_probe(const ToolArgs& args);
    ToolResponse handle_memory_dump(const ToolArgs& args);
    ToolResponse handle_memory_search(const ToolArgs& args);
    ToolResponse handle_memory_patch(const ToolArgs& args);
    ToolResponse handle_process_list(const ToolArgs& args);
    ToolResponse handle_translate_phys2virt(const ToolArgs& args);
    ToolResponse handle_translate_virt2phys(const ToolArgs& args);
    ToolResponse handle_process_virt2phys(const ToolArgs& args);
    ToolResponse handle_kmd_load(const ToolArgs& args);
    ToolResponse handle_kmd_exit(const ToolArgs& args);
    ToolResponse handle_kmd_execute(const ToolArgs& args);
    ToolResponse handle_kmd_list_scripts(const ToolArgs& args);
    ToolResponse handle_benchmark(const ToolArgs& args);
    ToolResponse handle_tlp_send(const ToolArgs& args);
    ToolResponse handle_fpga_config(const ToolArgs& args);

    PCILeechWrapper& get_pcileech();
    void validate_mutually_exclusive(const ToolArgs& args, const std::vector<string>& param_names, const string& tool_name);
    bool isDMAWorking() const;
    
    std::vector<Tool> get_available_tools() const;
    ToolResponse call_tool(const string& name, const ToolArgs& args);
    
    string get_string_param(const ToolArgs& args, const string& key);
    uint32_t get_int_param(const ToolArgs& args, const string& key);
    std::optional<uint32_t> get_optional_int_param(const ToolArgs& args, const string& key);
    std::optional<string> get_optional_string_param(const ToolArgs& args, const string& key);
    string get_optional_string_param(const ToolArgs& args, const string& key, const string& default_val);
    bool get_optional_bool_param(const ToolArgs& args, const string& key, bool default_val);
    double get_optional_double_param(const ToolArgs& args, const string& key, double default_val);
    std::optional<std::vector<JsonValue>> get_optional_array_param(const ToolArgs& args, const string& key);

    Tool create_memory_read_tool() const;
    Tool create_memory_write_tool() const;
    Tool create_memory_format_tool() const;
    Tool create_system_info_tool() const;
    Tool create_memory_probe_tool() const;
    Tool create_memory_dump_tool() const;
    Tool create_memory_search_tool() const;
    Tool create_memory_patch_tool() const;
    Tool create_process_list_tool() const;
    Tool create_translate_phys2virt_tool() const;
    Tool create_translate_virt2phys_tool() const;
    Tool create_process_virt2phys_tool() const;
    Tool create_kmd_load_tool() const;
    Tool create_kmd_exit_tool() const;
    Tool create_kmd_execute_tool() const;
    Tool create_kmd_list_scripts_tool() const;
    Tool create_benchmark_tool() const;
    Tool create_tlp_send_tool() const;
    Tool create_fpga_config_tool() const;

    static constexpr const char* JSONRPC_VERSION = "2.0";
    static constexpr const char* METHOD_INITIALIZE = "initialize";
    static constexpr const char* METHOD_LIST_TOOLS = "tools/list";
    static constexpr const char* METHOD_CALL_TOOL = "tools/call";

    static constexpr int JSONRPC_ERROR_PARSE_ERROR = -32700;
    static constexpr int JSONRPC_ERROR_INVALID_REQUEST = -32600;
    static constexpr int JSONRPC_ERROR_METHOD_NOT_FOUND = -32601;
    static constexpr int JSONRPC_ERROR_INVALID_PARAMS = -32602;
    static constexpr int JSONRPC_ERROR_INTERNAL_ERROR = -32603;

    static constexpr const char* TOOL_MEMORY_READ = "memory_read";
    static constexpr const char* TOOL_MEMORY_WRITE = "memory_write";
    static constexpr const char* TOOL_MEMORY_FORMAT = "memory_format";
    static constexpr const char* TOOL_SYSTEM_INFO = "system_info";
    static constexpr const char* TOOL_MEMORY_PROBE = "memory_probe";
    static constexpr const char* TOOL_MEMORY_DUMP = "memory_dump";
    static constexpr const char* TOOL_MEMORY_SEARCH = "memory_search";
    static constexpr const char* TOOL_MEMORY_PATCH = "memory_patch";
    static constexpr const char* TOOL_PROCESS_LIST = "process_list";
    static constexpr const char* TOOL_TRANSLATE_PHYS2VIRT = "translate_phys2virt";
    static constexpr const char* TOOL_TRANSLATE_VIRT2PHYS = "translate_virt2phys";
    static constexpr const char* TOOL_PROCESS_VIRT2PHYS = "process_virt2phys";
    static constexpr const char* TOOL_KMD_LOAD = "kmd_load";
    static constexpr const char* TOOL_KMD_EXIT = "kmd_exit";
    static constexpr const char* TOOL_KMD_EXECUTE = "kmd_execute";
    static constexpr const char* TOOL_KMD_LIST_SCRIPTS = "kmd_list_scripts";
    static constexpr const char* TOOL_BENCHMARK = "benchmark";
    static constexpr const char* TOOL_TLP_SEND = "tlp_send";
    static constexpr const char* TOOL_FPGA_CONFIG = "fpga_config";
};

}
