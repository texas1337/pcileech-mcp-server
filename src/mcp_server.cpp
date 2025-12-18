#include "mcp_server.hpp"
#include "config.hpp"
#include "utils.hpp"
#include <algorithm>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <sstream>
#include <thread>
#include <atomic>

namespace mcp_server_pcileech {

MCPServer::MCPServer(const Config& config) : config_(config), running_(false) {}

void MCPServer::run() {
    running_ = true;

    if (config_.validate()) {
        try {
            get_pcileech();
        } catch (const std::exception&) {
        }
    }
    std::string line;
    while (running_) {
        if (!std::getline(std::cin, line)) {
            if (std::cin.eof()) {
                running_ = false;
                break;
            }
            if (std::cin.fail()) {
                running_ = false;
                break;
            }
            continue;
        }
        if (line.empty()) continue;
        try {
            json message = json::parse(line);
            handle_message(message);
        } catch (const std::exception& e) {
            send_error(JSONRPC_ERROR_PARSE_ERROR, "Parse error: " + std::string(e.what()), json());
        }
    }
}

void MCPServer::handle_message(const json& message) {
    if (!message.contains("jsonrpc") || message["jsonrpc"].get<std::string>() != "2.0") {
        send_error(JSONRPC_ERROR_INVALID_REQUEST, "Invalid JSON-RPC version", message.value("id", json()));
        return;
    }

    if (!message.contains("method")) {
        send_error(JSONRPC_ERROR_INVALID_REQUEST, "Missing method", message.value("id", json()));
        return;
    }

    string method = message["method"].get<string>();
    json id = message.value("id", json());

    if (method == METHOD_INITIALIZE) {
        handle_initialize(message);
    } else if (method == METHOD_LIST_TOOLS) {
        handle_list_tools(message);
    } else if (method == METHOD_CALL_TOOL) {
        handle_call_tool(message);
    } else if (method == "shutdown" || method == "exit" || method == "poweroff" || method == "signout") {
        handle_shutdown(message);
    } else {
        send_error(JSONRPC_ERROR_METHOD_NOT_FOUND, "Method not found: " + method, id);
    }
}

void MCPServer::handle_initialize(const json& message) {
    json response = {
        {"jsonrpc", "2.0"},
        {"id", message["id"]},
        {"result", {
            {"protocolVersion", "2024-11-05"},
            {"capabilities", {
                {"tools", {
                    {"listChanged", false}
                }}
            }},
            {"serverInfo", {
                {"name", config_.get_server_config().name},
                {"version", config_.get_server_config().version}
            }}
        }}
    };

        send_response(response);
}

void MCPServer::handle_shutdown(const json& message) {
    json response = {
        {"jsonrpc", "2.0"},
        {"id", message.value("id", json())},
        {"result", {
            {"message", "Shutting down server"}
        }}
    };
    send_response(response);
    running_ = false;
}

void MCPServer::handle_list_tools(const json& message) {
    std::vector<Tool> tools = get_available_tools();
    json tools_array = json::array();

    for (const auto& tool : tools) {
        tools_array.push_back(tool.to_json());
    }

    json response = {
        {"jsonrpc", "2.0"},
        {"id", message["id"]},
        {"result", {
            {"tools", tools_array}
        }}
    };

    send_response(response);
}

void MCPServer::handle_call_tool(const json& message) {
    if (!message.contains("params") || !message["params"].contains("name")) {
        send_error(JSONRPC_ERROR_INVALID_PARAMS, "Missing tool name", message.value("id", json()));
        return;
    }

    string tool_name = message["params"]["name"].get<string>();

    ToolArgs args;

    if (message["params"].contains("arguments")) {
        const json& arguments = message["params"]["arguments"];
        for (auto it = arguments.begin(); it != arguments.end(); ++it) {
            args[it.key()] = json_to_variant(it.value());
        }
    }

    try {
        ToolResponse result = call_tool(tool_name, args);

        json response = {
            {"jsonrpc", "2.0"},
            {"id", message["id"]},
            {"result", result.to_json()}
        };

        send_response(response);
    } catch (const PCILeechError& e) {
        send_error(JSONRPC_ERROR_INTERNAL_ERROR, std::string("PCILeech error: ") + e.what(), message.value("id", json()));
    } catch (const std::exception& e) {
        send_error(JSONRPC_ERROR_INTERNAL_ERROR, std::string("Internal error: ") + e.what(), message.value("id", json()));
    }
}

void MCPServer::send_response(const json& response) {
    std::cout << response.dump() << std::endl;
}

void MCPServer::send_error(int code, const string& message, const json& id) {
    json error_response = {
        {"jsonrpc", "2.0"},
        {"id", id},
        {"error", {
            {"code", code},
            {"message", message}
        }}
    };

    send_response(error_response);
}

std::vector<Tool> MCPServer::get_available_tools() const {
    return {
        create_memory_read_tool(),
        create_memory_write_tool(),
        create_memory_format_tool(),
        create_system_info_tool(),
        create_memory_probe_tool(),
        create_memory_dump_tool(),
        create_memory_search_tool(),
        create_memory_patch_tool(),
        create_process_list_tool(),
        create_translate_phys2virt_tool(),
        create_translate_virt2phys_tool(),
        create_process_virt2phys_tool(),
        create_kmd_load_tool(),
        create_kmd_exit_tool(),
        create_kmd_execute_tool(),
        create_kmd_list_scripts_tool(),
        create_benchmark_tool(),
        create_tlp_send_tool(),
        create_fpga_config_tool()
    };
}

ToolResponse MCPServer::call_tool(const string& name, const ToolArgs& args) {
    if (name == TOOL_MEMORY_READ) {
        return handle_memory_read(args);
    } else if (name == TOOL_MEMORY_WRITE) {
        return handle_memory_write(args);
    } else if (name == TOOL_MEMORY_FORMAT) {
        return handle_memory_format(args);
    } else if (name == TOOL_SYSTEM_INFO) {
        return handle_system_info(args);
    } else if (name == TOOL_MEMORY_PROBE) {
        return handle_memory_probe(args);
    } else if (name == TOOL_MEMORY_DUMP) {
        return handle_memory_dump(args);
    } else if (name == TOOL_MEMORY_SEARCH) {
        return handle_memory_search(args);
    } else if (name == TOOL_MEMORY_PATCH) {
        return handle_memory_patch(args);
    } else if (name == TOOL_PROCESS_LIST) {
        return handle_process_list(args);
    } else if (name == TOOL_TRANSLATE_PHYS2VIRT) {
        return handle_translate_phys2virt(args);
    } else if (name == TOOL_TRANSLATE_VIRT2PHYS) {
        return handle_translate_virt2phys(args);
    } else if (name == TOOL_PROCESS_VIRT2PHYS) {
        return handle_process_virt2phys(args);
    } else if (name == TOOL_KMD_LOAD) {
        return handle_kmd_load(args);
    } else if (name == TOOL_KMD_EXIT) {
        return handle_kmd_exit(args);
    } else if (name == TOOL_KMD_EXECUTE) {
        return handle_kmd_execute(args);
    } else if (name == TOOL_KMD_LIST_SCRIPTS) {
        return handle_kmd_list_scripts(args);
    } else if (name == TOOL_BENCHMARK) {
        return handle_benchmark(args);
    } else if (name == TOOL_TLP_SEND) {
        return handle_tlp_send(args);
    } else if (name == TOOL_FPGA_CONFIG) {
        return handle_fpga_config(args);
    } else {
        throw PCILeechError("Unknown tool: " + name);
    }
}

PCILeechWrapper& MCPServer::get_pcileech() {
    std::lock_guard<std::mutex> lock(pcileech_mutex_);
    if (!pcileech_) {
        pcileech_ = std::make_unique<PCILeechWrapper>(config_);
    }
    return *pcileech_;
}

void MCPServer::validate_mutually_exclusive(const ToolArgs& args, const std::vector<string>& param_names, const string& tool_name) {
    std::vector<string> provided;
    for (const auto& param : param_names) {
        if (args.find(param) != args.end()) {
            provided.push_back(param);
        }
    }

    if (provided.size() > 1) {
        throw PCILeechError("Tool '" + tool_name + "': Parameters " +
                          utils::join(provided, ", ") + " are mutually exclusive - only one can be specified");
    }
}

ToolResponse MCPServer::handle_memory_read(const ToolArgs& args) {
    string address = get_string_param(args, "address");
    size_t length = get_int_param(args, "length");
    auto pid = get_optional_int_param(args, "pid");
    auto process_name = get_optional_string_param(args, "process_name");

    validate_mutually_exclusive(args, {"pid", "process_name"}, TOOL_MEMORY_READ);

    string mode = "physical";
    if (pid) mode = "virtual (PID: " + std::to_string(*pid) + ")";
    else if (process_name) mode = "virtual (Process: " + *process_name + ")";

    auto& pcileech = get_pcileech();
    MemoryData data = pcileech.read_memory(address, length, pid, process_name);

    string result_text = "Successfully read " + std::to_string(data.size()) +
                        " bytes from " + address + " (" + mode + ")\n\n" +
                        "Hex data: " + utils::bytes_to_hex(data);

    return {{{"text", result_text}}};
}

ToolResponse MCPServer::handle_memory_write(const ToolArgs& args) {
    string address = get_string_param(args, "address");
    string data_hex = get_string_param(args, "data");
    auto pid = get_optional_int_param(args, "pid");
    auto process_name = get_optional_string_param(args, "process_name");

    validate_mutually_exclusive(args, {"pid", "process_name"}, TOOL_MEMORY_WRITE);

    if (!utils::is_valid_hex(data_hex)) {
        throw PCILeechError("Invalid hex data format");
    }

    MemoryData data = utils::hex_to_bytes(data_hex);
    if (data.size() > 1024 * 1024) {
        throw PCILeechError("Data too large: " + std::to_string(data.size()) +
                          " bytes exceeds maximum 1MB");
    }

    string mode = "physical";
    if (pid) mode = "virtual (PID: " + std::to_string(*pid) + ")";
    else if (process_name) mode = "virtual (Process: " + *process_name + ")";

    auto& pcileech = get_pcileech();
    bool success = pcileech.write_memory(address, data, pid, process_name);

    string result_text = "Successfully wrote " + std::to_string(data.size()) +
                        " bytes to " + address + " (" + mode + ")\n\n" +
                        "Data: " + data_hex;

    return {{{"text", result_text}}};
}

ToolResponse MCPServer::handle_memory_format(const ToolArgs& args) {
    string address = get_string_param(args, "address");
    size_t length = get_int_param(args, "length");
    auto formats = get_optional_array_param(args, "formats");
    auto pid = get_optional_int_param(args, "pid");
    auto process_name = get_optional_string_param(args, "process_name");

    validate_mutually_exclusive(args, {"pid", "process_name"}, TOOL_MEMORY_FORMAT);

    if (length > 4096) {
        throw PCILeechError("Length " + std::to_string(length) +
                          " exceeds maximum 4096 bytes for formatted output");
    }

    std::vector<string> format_list = {"hexdump", "ascii", "bytes", "dwords", "raw"};
    if (formats) {
        format_list.clear();
        for (const auto& format : *formats) {
            if (!format.is_string()) {
                throw PCILeechError("Invalid 'formats' value: expected array of strings");
            }
            format_list.push_back(format.get<string>());
        }

        if (format_list.empty()) {
            format_list = {"hexdump", "ascii", "bytes", "dwords", "raw"};
        }
    }

    string mode = "physical";
    if (pid) mode = "virtual (PID: " + std::to_string(*pid) + ")";
    else if (process_name) mode = "virtual (Process: " + *process_name + ")";

    auto& pcileech = get_pcileech();
    auto views = pcileech.format_memory(address, length, format_list, pid, process_name);

    std::ostringstream oss;
    oss << "Memory at " << address << " (" << length << " bytes, " << mode << ")\n";
    oss << std::string(80, '=') << "\n\n";

    if (std::find(format_list.begin(), format_list.end(), "hexdump") != format_list.end()) {
        oss << "## Hex Dump (with ASCII):\n" << views.hex_dump << "\n\n";
    }

    if (std::find(format_list.begin(), format_list.end(), "ascii") != format_list.end()) {
        oss << "## ASCII View:\n" << views.ascii_view << "\n\n";
    }

    if (std::find(format_list.begin(), format_list.end(), "bytes") != format_list.end()) {
        oss << "## Byte Array (decimal):\n" << views.byte_array << "\n\n";
    }

    if (std::find(format_list.begin(), format_list.end(), "dwords") != format_list.end()) {
        oss << "## DWORD Array (little-endian uint32):\n" << views.dword_array << "\n\n";
    }

    if (std::find(format_list.begin(), format_list.end(), "raw") != format_list.end()) {
        oss << "## Raw Hex:\n" << views.raw_hex << "\n\n";
    }

    return {{{"text", oss.str()}}};
}

ToolResponse MCPServer::handle_system_info(const ToolArgs& args) {
    bool verbose = get_optional_bool_param(args, "verbose", false);

    auto& pcileech = get_pcileech();
    SystemInfo info = pcileech.get_system_info(verbose);

    std::ostringstream oss;
    oss << "## PCILeech System Information\n";
    oss << std::string(50, '=') << "\n\n";

    if (info.device) {
        oss << "**Device:** " << *info.device << "\n";
    }
    if (info.fpga) {
        oss << "**Type:** FPGA-based device\n";
    }
    if (info.memory_max) {
        oss << "**Max Memory:** " << *info.memory_max << "\n";
    }

    oss << "\n### Raw Output:\n```\n" << info.raw_output << "\n```";

    return {{{"text", oss.str()}}};
}

ToolResponse MCPServer::handle_memory_probe(const ToolArgs& args) {
    string min_addr = get_optional_string_param(args, "min_address", "0x0");
    auto max_addr = get_optional_string_param(args, "max_address");

    auto& pcileech = get_pcileech();
    auto regions = pcileech.probe_memory(min_addr, max_addr);

    std::ostringstream oss;
    oss << "## Memory Probe Results\n";
    oss << std::string(50, '=') << "\n\n";

    if (regions.empty()) {
        oss << "No readable memory regions found.";
    } else {
        oss << "Found " << regions.size() << " memory region(s):\n\n";
        for (size_t i = 0; i < regions.size(); ++i) {
            const auto& region = regions[i];
            oss << (i + 1) << ". **" << utils::uint64_to_hex(region.start, true)
                << "** - **" << utils::uint64_to_hex(region.end, true)
                << "** (" << std::fixed << std::setprecision(2) << region.size_mb
                << " MB) - " << region.status << "\n";
        }
    }

    return {{{"text", oss.str()}}};
}

ToolResponse MCPServer::handle_memory_dump(const ToolArgs& args) {
    string min_addr = get_string_param(args, "min_address");
    string max_addr = get_string_param(args, "max_address");
    auto output_file = get_optional_string_param(args, "output_file");
    bool force = get_optional_bool_param(args, "force", false);

    auto& pcileech = get_pcileech();
    auto result = pcileech.dump_memory(min_addr, max_addr, output_file, force);

    std::ostringstream oss;
    oss << "## Memory Dump Result\n";
    oss << std::string(50, '=') << "\n\n";
    oss << "**Range:** " << result.min_address << " - " << result.max_address << "\n";
    oss << "**Success:** " << (result.success ? "Yes" : "No") << "\n";

    if (result.file) {
        oss << "**Output File:** " << *result.file << "\n";
    }

    oss << "\n### Command Output:\n```\n" << result.output << "\n```";

    return {{{"text", oss.str()}}};
}

ToolResponse MCPServer::handle_memory_search(const ToolArgs& args) {
    auto pattern = get_optional_string_param(args, "pattern");
    auto signature = get_optional_string_param(args, "signature");
    auto min_addr = get_optional_string_param(args, "min_address");
    auto max_addr = get_optional_string_param(args, "max_address");
    bool find_all = get_optional_bool_param(args, "find_all", false);

    validate_mutually_exclusive(args, {"pattern", "signature"}, TOOL_MEMORY_SEARCH);

    if (!pattern && !signature) {
        throw PCILeechError("Either 'pattern' or 'signature' must be provided");
    }

    string search_term = pattern ? *pattern : ("signature:" + *signature);

    auto& pcileech = get_pcileech();
    auto matches = pcileech.search_memory(pattern, signature, min_addr, max_addr, find_all);

    std::ostringstream oss;
    oss << "## Memory Search Results\n";
    oss << std::string(50, '=') << "\n\n";
    oss << "**Search:** " << search_term << "\n";
    oss << "**Range:** " << (min_addr ? *min_addr : "0x0") << " - "
        << (max_addr ? *max_addr : "max") << "\n\n";

    if (matches.empty()) {
        oss << "**No matches found.**";
    } else {
        oss << "**Found " << matches.size() << " match(es):**\n\n";
        for (size_t i = 0; i < matches.size(); ++i) {
            oss << (i + 1) << ". Address: **" << matches[i].address << "**\n";
            if (!matches[i].line.empty()) {
                oss << "   Context: " << matches[i].line << "\n";
            }
        }
    }

    return {{{"text", oss.str()}}};
}

ToolResponse MCPServer::handle_memory_patch(const ToolArgs& args) {
    string signature = get_string_param(args, "signature");
    auto min_addr = get_optional_string_param(args, "min_address");
    auto max_addr = get_optional_string_param(args, "max_address");
    bool patch_all = get_optional_bool_param(args, "patch_all", false);

    auto& pcileech = get_pcileech();
    auto result = pcileech.patch_memory(signature, min_addr, max_addr, patch_all);

    std::ostringstream oss;
    oss << "## Memory Patch Result\n";
    oss << std::string(50, '=') << "\n\n";
    oss << "**Signature:** " << result.signature << "\n";
    oss << "**Success:** " << (result.success ? "Yes" : "No") << "\n";
    oss << "**Matches Found:** " << result.matches_found << "\n";
    oss << "**Patches Applied:** " << result.patches_applied << "\n\n";
    oss << "### Command Output:\n```\n" << result.output << "\n```";

    return {{{"text", oss.str()}}};
}

ToolResponse MCPServer::handle_process_list(const ToolArgs& args) {
    auto& pcileech = get_pcileech();
    auto processes = pcileech.list_processes();

    std::ostringstream oss;
    oss << "## Process List\n";
    oss << std::string(50, '=') << "\n\n";

    if (processes.empty()) {
        oss << "No processes found or unable to enumerate.";
    } else {
        oss << "Found " << processes.size() << " process(es):\n\n";
        oss << "| PID | PPID | Name |\n";
        oss << "|-----|------|------|\n";

        for (const auto& proc : processes) {
            oss << "| " << proc.pid << " | "
                << (proc.ppid ? std::to_string(*proc.ppid) : "-") << " | "
                << proc.name << " |\n";
        }
    }

    return {{{"text", oss.str()}}};
}

ToolResponse MCPServer::handle_translate_phys2virt(const ToolArgs& args) {
    string phys_addr = get_string_param(args, "physical_address");
    string cr3 = get_string_param(args, "cr3");

    auto& pcileech = get_pcileech();
    auto result = pcileech.translate_phys2virt(phys_addr, cr3);

    std::ostringstream oss;
    oss << "## Physical to Virtual Address Translation\n";
    oss << std::string(50, '=') << "\n\n";
    oss << "**Physical Address:** " << (result.physical ? utils::uint64_to_hex(*result.physical, true) : string("Not found")) << "\n";
    oss << "**CR3 (Page Table Base):** " << utils::uint64_to_hex(result.cr3, true) << "\n";
    oss << "**Virtual Address:** " << (result.virtual_addr ? utils::uint64_to_hex(*result.virtual_addr, true) : string("Not found")) << "\n";
    oss << "**Success:** " << (result.success ? "Yes" : "No") << "\n\n";
    oss << "### Command Output:\n```\n" << result.output << "\n```";

    return {{{"text", oss.str()}}};
}

ToolResponse MCPServer::handle_translate_virt2phys(const ToolArgs& args) {
    string virt_addr = get_string_param(args, "virtual_address");
    string cr3 = get_string_param(args, "cr3");

    auto& pcileech = get_pcileech();
    auto result = pcileech.translate_virt2phys(virt_addr, cr3);

    std::ostringstream oss;
    oss << "## Virtual to Physical Address Translation\n";
    oss << std::string(50, '=') << "\n\n";
    oss << "**Virtual Address:** " << virt_addr << "\n";
    oss << "**CR3 (Page Table Base):** " << utils::uint64_to_hex(result.cr3, true) << "\n";
    oss << "**Physical Address:** " << (result.physical ? utils::uint64_to_hex(*result.physical, true) : string("Not found")) << "\n";
    oss << "**Success:** " << (result.success ? "Yes" : "No") << "\n\n";
    oss << "### Command Output:\n```\n" << result.output << "\n```";

    return {{{"text", oss.str()}}};
}

ToolResponse MCPServer::handle_process_virt2phys(const ToolArgs& args) {
    uint32_t pid = get_int_param(args, "pid");
    string virt_addr = get_string_param(args, "virtual_address");

    auto& pcileech = get_pcileech();
    auto result = pcileech.process_virt2phys(pid, virt_addr);

    std::ostringstream oss;
    oss << "## Process Virtual to Physical Address Translation\n";
    oss << std::string(50, '=') << "\n\n";
    oss << "**Process ID:** " << result.pid << "\n";
    oss << "**Virtual Address:** " << utils::uint64_to_hex(result.virtual_addr, true) << "\n";
    oss << "**Physical Address:** " << (result.physical ? utils::uint64_to_hex(*result.physical, true) : string("Not found")) << "\n";
    oss << "**Success:** " << (result.success ? "Yes" : "No") << "\n\n";
    oss << "### Command Output:\n```\n" << result.output << "\n```";

    return {{{"text", oss.str()}}};
}

ToolResponse MCPServer::handle_kmd_load(const ToolArgs& args) {
    string kmd_type = get_string_param(args, "kmd_type");
    bool use_pt = get_optional_bool_param(args, "use_page_table", false);
    auto cr3 = get_optional_string_param(args, "cr3");
    auto sysmap = get_optional_string_param(args, "sysmap");

    auto& pcileech = get_pcileech();
    auto result = pcileech.load_kmd(kmd_type, use_pt, cr3, sysmap);

    std::ostringstream oss;
    oss << "## Kernel Module Load Result\n";
    oss << std::string(50, '=') << "\n\n";
    oss << "**KMD Type:** " << result.kmd_type << "\n";
    oss << "**Success:** " << (result.success ? "Yes" : "No") << "\n";
    oss << "**KMD Address:** " << (result.kmd_address ? *result.kmd_address : "Unknown") << "\n\n";

    if (result.success) {
        oss << "[!] **WARNING:** KMD is now loaded in target kernel memory!\n";
        oss << "Remember to unload with `kmd_exit` when done.\n\n";
    }

    oss << "### Command Output:\n```\n" << result.output << "\n```";

    if (result.error) {
        oss << "\n### Error:\n" << *result.error;
    }

    return {{{"text", oss.str()}}};
}

ToolResponse MCPServer::handle_kmd_exit(const ToolArgs& args) {
    auto kmd_address = get_optional_string_param(args, "kmd_address");

    auto& pcileech = get_pcileech();
    auto result = pcileech.unload_kmd(kmd_address);

    std::ostringstream oss;
    oss << "## Kernel Module Unload Result\n";
    oss << std::string(50, '=') << "\n\n";
    oss << "**KMD Address:** " << result.kmd_address << "\n";
    oss << "**Success:** " << (result.success ? "Yes" : "No") << "\n\n";

    if (result.success) {
        oss << "[OK] KMD successfully unloaded from target system.";
    } else if (result.error) {
        oss << "### Error:\n```\n" << *result.error << "\n```";
    }

    oss << "\n### Command Output:\n```\n" << result.output << "\n```";

    return {{{"text", oss.str()}}};
}

ToolResponse MCPServer::handle_kmd_execute(const ToolArgs& args) {
    string script_name = get_string_param(args, "script_name");
    auto kmd_address = get_optional_string_param(args, "kmd_address");
    auto input_file = get_optional_string_param(args, "input_file");
    auto output_file = get_optional_string_param(args, "output_file");
    auto string_param = get_optional_string_param(args, "string_param");

    std::unordered_map<string, string> numeric_params;
    for (int i = 0; i <= 3; ++i) {
        auto param = get_optional_string_param(args, "param_" + std::to_string(i));
        if (param) {
            numeric_params[std::to_string(i)] = *param;
        }
    }

    auto& pcileech = get_pcileech();
    auto result = pcileech.execute_ksh(script_name, kmd_address, input_file, output_file,
                                     string_param, numeric_params.empty() ? std::nullopt : std::make_optional(numeric_params));

    std::ostringstream oss;
    oss << "## Kernel Script Execution Result\n";
    oss << std::string(50, '=') << "\n\n";
    oss << "**Script:** " << result.script << "\n";
    oss << "**KMD Address:** " << result.kmd_address << "\n";
    oss << "**Success:** " << (result.success ? "Yes" : "No") << "\n\n";
    oss << "### Script Output:\n```\n" << result.output << "\n```";

    if (result.error) {
        oss << "\n### Error:\n" << *result.error;
    }

    return {{{"text", oss.str()}}};
}

ToolResponse MCPServer::handle_kmd_list_scripts(const ToolArgs& args) {
    string platform = get_optional_string_param(args, "platform", "all");

    auto& pcileech = get_pcileech();
    auto scripts = pcileech.list_available_scripts(platform);

    std::ostringstream oss;
    oss << "## Available Kernel Scripts (.ksh)\n";
    oss << std::string(50, '=') << "\n\n";
    oss << "**Platform Filter:** " << platform << "\n";
    oss << "**Total Scripts:** " << scripts.size() << "\n\n";

    if (scripts.empty()) {
        oss << "No scripts found for the specified platform.";
    } else {
        std::map<string, std::vector<KernelScript>> grouped;
        for (const auto& script : scripts) {
            grouped[script.platform].push_back(script);
        }

        for (const auto& [plat, script_list] : grouped) {
            oss << "\n### " << utils::to_upper(plat) << "\n\n";
            for (const auto& script : script_list) {
                oss << "- `" << script.name << "`\n";
            }
        }
    }

    return {{{"text", oss.str()}}};
}

ToolResponse MCPServer::handle_benchmark(const ToolArgs& args) {
    string test_type = get_optional_string_param(args, "test_type", "read");
    string address = get_optional_string_param(args, "address", "0x1000");

    auto& pcileech = get_pcileech();
    auto result = pcileech.run_benchmark(test_type, address);

    std::ostringstream oss;
    oss << "## Memory Benchmark Result\n";
    oss << std::string(50, '=') << "\n\n";
    oss << "**Test Type:** " << result.test_type << "\n";
    oss << "**Address:** " << result.address << "\n";
    oss << "**Success:** " << (result.success ? "Yes" : "No") << "\n";

    if (result.speed_mbps) {
        oss << "**Speed:** " << std::fixed << std::setprecision(2) << *result.speed_mbps << " MB/s\n";
    }

    oss << "\n### Command Output:\n```\n" << result.output << "\n```";

    return {{{"text", oss.str()}}};
}

ToolResponse MCPServer::handle_tlp_send(const ToolArgs& args) {
    auto tlp_data = get_optional_string_param(args, "tlp_data");
    double wait_seconds = get_optional_double_param(args, "wait_seconds", 0.5);
    bool verbose = get_optional_bool_param(args, "verbose", true);

    string action = tlp_data ? "Sending TLP" : "Listening for TLP";

    auto& pcileech = get_pcileech();
    auto result = pcileech.send_tlp(tlp_data, wait_seconds, verbose);

    std::ostringstream oss;
    oss << "## PCIe TLP Operation Result\n";
    oss << std::string(50, '=') << "\n\n";
    oss << "**Action:** " << action << "\n";
    oss << "**Wait Time:** " << std::fixed << std::setprecision(1) << result.wait_seconds << "s\n";
    oss << "**Success:** " << (result.success ? "Yes" : "No") << "\n";

    if (tlp_data) {
        oss << "**TLP Sent:** " << *tlp_data << "\n";
    }

    if (!result.tlp_received.empty()) {
        oss << "\n**TLP Received (" << result.tlp_received.size() << "):**\n";
        for (size_t i = 0; i < result.tlp_received.size(); ++i) {
            oss << "  " << (i + 1) << ". " << result.tlp_received[i] << "\n";
        }
    }

    oss << "\n### Command Output:\n```\n" << result.output << "\n```";

    return {{{"text", oss.str()}}};
}

ToolResponse MCPServer::handle_fpga_config(const ToolArgs& args) {
    string action = get_optional_string_param(args, "action", "read");
    auto address = get_optional_string_param(args, "address");
    auto data = get_optional_string_param(args, "data");
    auto output_file = get_optional_string_param(args, "output_file");

    auto& pcileech = get_pcileech();
    auto result = pcileech.fpga_config(action, address, data, output_file);

    std::ostringstream oss;
    oss << "## FPGA Configuration Space Result\n";
    oss << std::string(50, '=') << "\n\n";
    oss << "**Action:** " << result.action << "\n";
    oss << "**Address:** " << (result.address ? *result.address : "Default") << "\n";
    oss << "**Success:** " << (result.success ? "Yes" : "No") << "\n";

    if (result.data) {
        oss << "\n**Data Read:**\n```\n" << *result.data << "\n```";
    }

    oss << "\n### Command Output:\n```\n" << result.output << "\n```";

    return {{{"text", oss.str()}}};
}

string MCPServer::get_string_param(const ToolArgs& args, const string& key) {
    auto it = args.find(key);
    if (it == args.end() || !it->second.is_string()) {
        throw PCILeechError("Missing or invalid parameter: " + key);
    }
    return it->second.get<string>();
}

uint32_t MCPServer::get_int_param(const ToolArgs& args, const string& key) {
    auto it = args.find(key);
    if (it == args.end()) {
        throw PCILeechError("Missing or invalid parameter: " + key);
    }

    const json& v = it->second;
    if (!v.is_number_integer() && !v.is_number_unsigned()) {
        throw PCILeechError("Missing or invalid parameter: " + key);
    }

    if (v.is_number_integer()) {
        const auto i = v.get<int64_t>();
        if (i < 0 || i > std::numeric_limits<uint32_t>::max()) {
            throw PCILeechError("Parameter '" + key + "' out of range");
        }
        return static_cast<uint32_t>(i);
    }

    const auto u = v.get<uint64_t>();
    if (u > std::numeric_limits<uint32_t>::max()) {
        throw PCILeechError("Parameter '" + key + "' out of range");
    }
    return static_cast<uint32_t>(u);
}

std::optional<uint32_t> MCPServer::get_optional_int_param(const ToolArgs& args, const string& key) {
    auto it = args.find(key);
    if (it == args.end()) {
        return std::nullopt;
    }

    const json& v = it->second;
    if (!v.is_number_integer() && !v.is_number_unsigned()) {
        throw PCILeechError("Parameter '" + key + "' must be an integer");
    }

    if (v.is_number_integer()) {
        const auto i = v.get<int64_t>();
        if (i < 0 || i > std::numeric_limits<uint32_t>::max()) {
            return std::nullopt;
        }
        return static_cast<uint32_t>(i);
    }

    const auto u = v.get<uint64_t>();
    if (u > std::numeric_limits<uint32_t>::max()) {
        return std::nullopt;
    }
    return static_cast<uint32_t>(u);
}

std::optional<string> MCPServer::get_optional_string_param(const ToolArgs& args, const string& key) {
    auto it = args.find(key);
    if (it == args.end()) {
        return std::nullopt;
    }
    if (!it->second.is_string()) {
        throw PCILeechError("Parameter '" + key + "' must be a string");
    }
    return it->second.get<string>();
}

string MCPServer::get_optional_string_param(const ToolArgs& args, const string& key, const string& default_val) {
    auto it = args.find(key);
    if (it == args.end()) {
        return default_val;
    }
    if (!it->second.is_string()) {
        throw PCILeechError("Parameter '" + key + "' must be a string");
    }
    return it->second.get<string>();
}

bool MCPServer::get_optional_bool_param(const ToolArgs& args, const string& key, bool default_val) {
    auto it = args.find(key);
    if (it == args.end()) {
        return default_val;
    }
    if (!it->second.is_boolean()) {
        throw PCILeechError("Parameter '" + key + "' must be a boolean");
    }
    return it->second.get<bool>();
}

double MCPServer::get_optional_double_param(const ToolArgs& args, const string& key, double default_val) {
    auto it = args.find(key);
    if (it == args.end()) {
        return default_val;
    }

    const json& v = it->second;
    if (!v.is_number()) {
        throw PCILeechError("Parameter '" + key + "' must be a number");
    }
    return v.get<double>();
}

std::optional<std::vector<JsonValue>> MCPServer::get_optional_array_param(const ToolArgs& args, const string& key) {
    auto it = args.find(key);
    if (it == args.end()) {
        return std::nullopt;
    }
    if (!it->second.is_array()) {
        throw PCILeechError("Parameter '" + key + "' must be an array");
    }
    return it->second.get<std::vector<JsonValue>>();
}

Tool MCPServer::create_memory_read_tool() const {
    return {
        TOOL_MEMORY_READ,
        "Read memory from specified address using PCILeech DMA. Supports both physical addresses and process virtual addresses.",
        {
            {"type", "object"},
            {"properties", {
                {"address", {
                    {"type", "string"},
                    {"description", "Memory address in hex format (e.g., '0x1000' or '1000')"}
                }},
                {"length", {
                    {"type", "integer"},
                    {"description", "Number of bytes to read"},
                    {"minimum", 1},
                    {"maximum", 1048576}
                }},
                {"pid", {
                    {"type", "integer"},
                    {"description", "Process ID for virtual address mode (optional)"}
                }},
                {"process_name", {
                    {"type", "string"},
                    {"description", "Process name for virtual address mode (optional, alternative to pid)"}
                }}
            }},
            {"required", {"address", "length"}}
        }
    };
}

Tool MCPServer::create_memory_write_tool() const {
    return {
        TOOL_MEMORY_WRITE,
        "Write data to memory at specified address using PCILeech DMA. Supports both physical addresses and process virtual addresses.",
        {
            {"type", "object"},
            {"properties", {
                {"address", {
                    {"type", "string"},
                    {"description", "Memory address in hex format (e.g., '0x1000' or '1000')"}
                }},
                {"data", {
                    {"type", "string"},
                    {"description", "Hex string of data to write (e.g., '48656c6c6f')"},
                    {"maxLength", 2097152}
                }},
                {"pid", {
                    {"type", "integer"},
                    {"description", "Process ID for virtual address mode (optional)"}
                }},
                {"process_name", {
                    {"type", "string"},
                    {"description", "Process name for virtual address mode (optional, alternative to pid)"}
                }}
            }},
            {"required", {"address", "data"}}
        }
    };
}

Tool MCPServer::create_memory_format_tool() const {
    return {
        TOOL_MEMORY_FORMAT,
        "Read memory and format in multiple views (hex dump, ASCII, byte array, DWORD array) for AI analysis. Supports both physical addresses and process virtual addresses.",
        {
            {"type", "object"},
            {"properties", {
                {"address", {
                    {"type", "string"},
                    {"description", "Memory address in hex format (e.g., '0x1000' or '1000')"}
                }},
                {"length", {
                    {"type", "integer"},
                    {"description", "Number of bytes to read"},
                    {"minimum", 1},
                    {"maximum", 4096}
                }},
                {"formats", {
                    {"type", "array"},
                    {"items", {
                        {"type", "string"},
                        {"enum", {"hexdump", "ascii", "bytes", "dwords", "raw"}}
                    }},
                    {"description", "Output formats to include (default: all)"},
                    {"default", {"hexdump", "ascii", "bytes", "dwords", "raw"}}
                }},
                {"pid", {
                    {"type", "integer"},
                    {"description", "Process ID for virtual address mode (optional)"}
                }},
                {"process_name", {
                    {"type", "string"},
                    {"description", "Process name for virtual address mode (optional, alternative to pid)"}
                }}
            }},
            {"required", {"address", "length"}}
        }
    };
}

Tool MCPServer::create_system_info_tool() const {
    return {
        TOOL_SYSTEM_INFO,
        "Get target system and PCILeech device information",
        {
            {"type", "object"},
            {"properties", {
                {"verbose", {
                    {"type", "boolean"},
                    {"description", "Include detailed information"},
                    {"default", false}
                }}
            }},
            {"required", {}}
        }
    };
}

Tool MCPServer::create_memory_probe_tool() const {
    return {
        TOOL_MEMORY_PROBE,
        "Probe target memory to find readable regions (FPGA only)",
        {
            {"type", "object"},
            {"properties", {
                {"min_address", {
                    {"type", "string"},
                    {"description", "Starting address in hex (default: 0x0)"},
                    {"default", "0x0"}
                }},
                {"max_address", {
                    {"type", "string"},
                    {"description", "Ending address in hex (default: auto-detect)"}
                }}
            }},
            {"required", {}}
        }
    };
}

Tool MCPServer::create_memory_dump_tool() const {
    return {
        TOOL_MEMORY_DUMP,
        "Dump memory range to file for offline analysis",
        {
            {"type", "object"},
            {"properties", {
                {"min_address", {
                    {"type", "string"},
                    {"description", "Starting address in hex"}
                }},
                {"max_address", {
                    {"type", "string"},
                    {"description", "Ending address in hex"}
                }},
                {"output_file", {
                    {"type", "string"},
                    {"description", "Output file path (auto-generated if not specified)"}
                }},
                {"force", {
                    {"type", "boolean"},
                    {"description", "Force read even if marked inaccessible"},
                    {"default", false}
                }}
            }},
            {"required", {"min_address", "max_address"}}
        }
    };
}

Tool MCPServer::create_memory_search_tool() const {
    return {
        TOOL_MEMORY_SEARCH,
        "Search memory for byte pattern or signature",
        {
            {"type", "object"},
            {"properties", {
                {"pattern", {
                    {"type", "string"},
                    {"description", "Hex pattern to search (e.g., '4D5A9000' for MZ header)"}
                }},
                {"signature", {
                    {"type", "string"},
                    {"description", "Signature file name without .sig extension"}
                }},
                {"min_address", {
                    {"type", "string"},
                    {"description", "Start address in hex"}
                }},
                {"max_address", {
                    {"type", "string"},
                    {"description", "End address in hex"}
                }},
                {"find_all", {
                    {"type", "boolean"},
                    {"description", "Find all matches instead of just first"},
                    {"default", false}
                }}
            }},
            {"required", {}}
        }
    };
}

Tool MCPServer::create_memory_patch_tool() const {
    return {
        TOOL_MEMORY_PATCH,
        "Search and patch memory using signature file",
        {
            {"type", "object"},
            {"properties", {
                {"signature", {
                    {"type", "string"},
                    {"description", "Signature file name without .sig extension"}
                }},
                {"min_address", {
                    {"type", "string"},
                    {"description", "Start address in hex"}
                }},
                {"max_address", {
                    {"type", "string"},
                    {"description", "End address in hex"}
                }},
                {"patch_all", {
                    {"type", "boolean"},
                    {"description", "Patch all matches instead of just first"},
                    {"default", false}
                }}
            }},
            {"required", {"signature"}}
        }
    };
}

Tool MCPServer::create_process_list_tool() const {
    return {
        TOOL_PROCESS_LIST,
        "List processes on target Windows system",
        {
            {"type", "object"},
            {"properties", {}},
            {"required", {}}
        }
    };
}

Tool MCPServer::create_translate_phys2virt_tool() const {
    return {
        TOOL_TRANSLATE_PHYS2VIRT,
        "Translate physical address to virtual address using page table",
        {
            {"type", "object"},
            {"properties", {
                {"physical_address", {
                    {"type", "string"},
                    {"description", "Physical address in hex format"}
                }},
                {"cr3", {
                    {"type", "string"},
                    {"description", "Page table base address (CR3 register value) in hex"}
                }}
            }},
            {"required", {"physical_address", "cr3"}}
        }
    };
}

Tool MCPServer::create_translate_virt2phys_tool() const {
    return {
        TOOL_TRANSLATE_VIRT2PHYS,
        "Translate virtual address to physical address using page table",
        {
            {"type", "object"},
            {"properties", {
                {"virtual_address", {
                    {"type", "string"},
                    {"description", "Virtual address in hex format"}
                }},
                {"cr3", {
                    {"type", "string"},
                    {"description", "Page table base address (CR3 register value) in hex"}
                }}
            }},
            {"required", {"virtual_address", "cr3"}}
        }
    };
}

Tool MCPServer::create_process_virt2phys_tool() const {
    return {
        TOOL_PROCESS_VIRT2PHYS,
        "Translate process virtual address to physical address",
        {
            {"type", "object"},
            {"properties", {
                {"pid", {
                    {"type", "integer"},
                    {"description", "Process ID"}
                }},
                {"virtual_address", {
                    {"type", "string"},
                    {"description", "Virtual address in hex format"}
                }}
            }},
            {"required", {"pid", "virtual_address"}}
        }
    };
}

Tool MCPServer::create_kmd_load_tool() const {
    return {
        TOOL_KMD_LOAD,
        "Load kernel module (KMD) to target system for enhanced memory access",
        {
            {"type", "object"},
            {"properties", {
                {"kmd_type", {
                    {"type", "string"},
                    {"enum", {
                        "WIN10_X64", "WIN10_X64_2", "WIN10_X64_3", "WIN11_X64",
                        "LINUX_X64_46", "LINUX_X64_48", "LINUX_X64_MAP", "LINUX_X64_EFI",
                        "FREEBSD_X64", "MACOS",
                        "UEFI_EXIT_BOOT_SERVICES", "UEFI_SIGNAL_EVENT"
                    }},
                    {"description", "Kernel module type for target OS"}
                }},
                {"use_page_table", {
                    {"type", "boolean"},
                    {"description", "Use page table hijacking method"},
                    {"default", false}
                }},
                {"cr3", {
                    {"type", "string"},
                    {"description", "Page table base address (optional)"}
                }},
                {"sysmap", {
                    {"type", "string"},
                    {"description", "Linux System.map file path (for LINUX_X64_MAP)"}
                }}
            }},
            {"required", {"kmd_type"}}
        }
    };
}

Tool MCPServer::create_kmd_exit_tool() const {
    return {
        TOOL_KMD_EXIT,
        "Unload kernel module (KMD) from target system",
        {
            {"type", "object"},
            {"properties", {
                {"kmd_address", {
                    {"type", "string"},
                    {"description", "KMD address in hex (uses cached address if not provided)"}
                }}
            }},
            {"required", {}}
        }
    };
}

Tool MCPServer::create_kmd_execute_tool() const {
    return {
        TOOL_KMD_EXECUTE,
        "Execute kernel script (.ksh) on target system via loaded KMD",
        {
            {"type", "object"},
            {"properties", {
                {"script_name", {
                    {"type", "string"},
                    {"description", "Script name without .ksh extension (e.g., 'wx64_pslist')"}
                }},
                {"kmd_address", {
                    {"type", "string"},
                    {"description", "KMD address (uses cached address if not provided)"}
                }},
                {"input_file", {
                    {"type", "string"},
                    {"description", "Input file path"}
                }},
                {"output_file", {
                    {"type", "string"},
                    {"description", "Output file path"}
                }},
                {"string_param", {
                    {"type", "string"},
                    {"description", "String parameter (-s)"}
                }},
                {"param_0", {{"type", "string"}, {"description", "Numeric param -0"}}},
                {"param_1", {{"type", "string"}, {"description", "Numeric param -1"}}},
                {"param_2", {{"type", "string"}, {"description", "Numeric param -2"}}},
                {"param_3", {{"type", "string"}, {"description", "Numeric param -3"}}}
            }},
            {"required", {"script_name"}}
        }
    };
}

Tool MCPServer::create_kmd_list_scripts_tool() const {
    return {
        TOOL_KMD_LIST_SCRIPTS,
        "List available kernel scripts (.ksh files)",
        {
            {"type", "object"},
            {"properties", {
                {"platform", {
                    {"type", "string"},
                    {"enum", {"all", "windows", "linux", "macos", "freebsd", "uefi"}},
                    {"description", "Filter by target platform"},
                    {"default", "all"}
                }}
            }},
            {"required", {}}
        }
    };
}

Tool MCPServer::create_benchmark_tool() const {
    return {
        TOOL_BENCHMARK,
        "Run memory read/write performance benchmark",
        {
            {"type", "object"},
            {"properties", {
                {"test_type", {
                    {"type", "string"},
                    {"enum", {"read", "readwrite", "full"}},
                    {"description", "Type of benchmark test"},
                    {"default", "read"}
                }},
                {"address", {
                    {"type", "string"},
                    {"description", "Test address in hex"},
                    {"default", "0x1000"}
                }}
            }},
            {"required", {}}
        }
    };
}

Tool MCPServer::create_tlp_send_tool() const {
    return {
        TOOL_TLP_SEND,
        "Send/receive PCIe TLP packets (FPGA only)",
        {
            {"type", "object"},
            {"properties", {
                {"tlp_data", {
                    {"type", "string"},
                    {"description", "TLP packet data in hex (optional, omit to just listen)"}
                }},
                {"wait_seconds", {
                    {"type", "number"},
                    {"description", "Time to wait for TLP responses"},
                    {"default", 0.5},
                    {"minimum", 0.1},
                    {"maximum", 60}
                }},
                {"verbose", {
                    {"type", "boolean"},
                    {"description", "Show detailed TLP info"},
                    {"default", true}
                }}
            }},
            {"required", {}}
        }
    };
}

Tool MCPServer::create_fpga_config_tool() const {
    return {
        TOOL_FPGA_CONFIG,
        "Read/write FPGA PCIe configuration space",
        {
            {"type", "object"},
            {"properties", {
                {"action", {
                    {"type", "string"},
                    {"enum", {"read", "write"}},
                    {"description", "Read or write configuration"},
                    {"default", "read"}
                }},
                {"address", {
                    {"type", "string"},
                    {"description", "Configuration space address in hex"}
                }},
                {"data", {
                    {"type", "string"},
                    {"description", "Data to write in hex (for write action)"}
                }},
                {"output_file", {
                    {"type", "string"},
                    {"description", "Output file path"}
                }}
            }},
            {"required", {}}
        }
    };
}

bool MCPServer::isDMAWorking() const {
    try {
        return pcileech_ && pcileech_->verify_connection();
    } catch (...) {
        return false;
    }
}

}
