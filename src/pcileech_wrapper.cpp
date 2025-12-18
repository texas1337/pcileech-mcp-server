#include "pcileech_wrapper.hpp"
#include "config.hpp"
#include "memory_formatter.hpp"
#include "utils.hpp"
#include <algorithm>
#include <filesystem>
#include <regex>
#include <sstream>
#include <iomanip>

namespace mcp_server_pcileech {
namespace fs = std::filesystem;

static std::optional<fs::path> find_existing_upwards(const fs::path& start_dir,
                                                     const std::vector<fs::path>& relative_candidates,
                                                     int max_parents = 6) {
    std::error_code ec;
    fs::path cur = start_dir;

    for (int i = 0; i < max_parents && !cur.empty(); ++i) {
        for (const auto& rel : relative_candidates) {
            fs::path candidate = cur / rel;
            if (fs::exists(candidate, ec) && !ec) {
                return candidate.lexically_normal();
            }
        }

        fs::path parent = cur.parent_path();
        if (parent == cur) break;
        cur = parent;
    }

    return std::nullopt;
}

static std::optional<fs::path> find_resource_file(const fs::path& filename,
                                                  bool include_scripts_subdir) {
    fs::path app_dir;
    try {
        app_dir = fs::path(utils::get_executable_directory());
    } catch (...) {
        app_dir = fs::current_path();
    }

    fs::path cwd = fs::current_path();

    std::vector<fs::path> rels;
    rels.push_back(filename);
    if (include_scripts_subdir) {
        rels.push_back(fs::path("scripts") / filename);
    }

    if (auto found = find_existing_upwards(app_dir, rels)) return found;
    if (auto found = find_existing_upwards(cwd, rels)) return found;

    return std::nullopt;
}

PCILeechWrapper::PCILeechWrapper(const Config& config) : config_(config) {
    if (!utils::path_exists(config_.get_absolute_executable_path())) {
        throw DeviceNotFoundError("PCILeech executable not found: " + config_.get_absolute_executable_path());
    }
}

bool PCILeechWrapper::verify_connection() {
    try {
        auto result = run_command({"info"});
        return result.return_code == 0;
    } catch (...) {
        return false;
    }
}

MemoryData PCILeechWrapper::read_memory(const string& address, size_t length,
                                       std::optional<uint32_t> pid,
                                       std::optional<string> process_name) {
    utils::validate_length(length, 1, 1024 * 1024);
    uint64_t addr = utils::parse_hex_address(address);
    utils::validate_address_range(addr, length);

    if (pid && process_name) {
        throw ValidationError("pid and process_name are mutually exclusive");
    }

    if (pid && *pid <= 0) {
        throw ValidationError("pid must be positive, got " + std::to_string(*pid));
    }

    if (process_name) {
        *process_name = utils::validate_process_name(*process_name);
    }

    return read_memory_chunked(address, length, pid, process_name);
}

bool PCILeechWrapper::write_memory(const string& address, const MemoryData& data,
                                  std::optional<uint32_t> pid,
                                  std::optional<string> process_name) {
    if (data.empty()) {
        throw ValidationError("data cannot be empty");
    }

    if (pid && process_name) {
        throw ValidationError("pid and process_name are mutually exclusive");
    }

    if (pid && *pid <= 0) {
        throw ValidationError("pid must be positive, got " + std::to_string(*pid));
    }

    if (process_name) {
        *process_name = utils::validate_process_name(*process_name);
    }

    uint64_t addr = utils::parse_hex_address(address);
    utils::validate_address_range(addr, data.size());

    auto args = build_memory_args("write", address, pid, process_name);
    string hex_data = utils::bytes_to_hex(data);
    args.push_back("-in");
    args.push_back(hex_data);

    auto result = run_command(args);

    if (result.return_code != 0) {
        throw MemoryAccessError("Memory write failed with exit code " + std::to_string(result.return_code));
    }
    return true;
}

MemoryFormatter::MemoryViews PCILeechWrapper::format_memory(const string& address, size_t length,
                                                          const std::vector<string>& formats,
                                                          std::optional<uint32_t> pid,
                                                          std::optional<string> process_name) {
    utils::validate_length(length, 1, 4096);
    auto data = read_memory(address, length, pid, process_name);
    return MemoryFormatter::format_all_views(data, address);
}

SystemInfo PCILeechWrapper::get_system_info(bool verbose) {
    std::vector<string> args = {"info"};
    if (verbose) {
        args.push_back("-v");
    }

    auto result = run_command(args);

    if (result.return_code != 0) {
        if (result.return_code == 1) {
            throw DeviceNotFoundError("PCILeech device not found or not connected");
        }
        throw PCILeechError("System info command failed with exit code " + std::to_string(result.return_code));
    }
    return parse_info_output("");
}

std::vector<MemoryRegion> PCILeechWrapper::probe_memory(const string& min_addr,
                                                      std::optional<string> max_addr) {
    std::vector<string> args = {"probe", "-min", min_addr};
    if (max_addr) {
        args.push_back("-max");
        args.push_back(*max_addr);
    }

    auto result = run_command(args);

    if (result.return_code != 0) {
        if (result.return_code == 1) {
            throw ProbeNotSupportedError("Memory probe only supported on FPGA devices");
        }
        throw PCILeechError("Memory probe failed");
    }

    return parse_probe_output("");
}

MemoryDumpResult PCILeechWrapper::dump_memory(const string& min_addr, const string& max_addr,
                                            std::optional<string> output_file, bool force) {
    std::vector<string> args = {"dump", "-min", min_addr, "-max", max_addr};

    if (output_file) {
        args.push_back("-out");
        args.push_back(*output_file);
    }

    if (force) {
        args.push_back("-force");
    }

    auto result = run_command(args);

    if (result.return_code != 0) {
        throw MemoryAccessError("Memory dump failed");
    }

    MemoryDumpResult dump_result;
    dump_result.min_address = min_addr;
    dump_result.max_address = max_addr;
    dump_result.success = true;
    dump_result.output = "";

    return dump_result;
}

std::vector<SearchMatch> PCILeechWrapper::search_memory(std::optional<string> pattern,
                                                      std::optional<string> signature,
                                                      std::optional<string> min_addr,
                                                      std::optional<string> max_addr,
                                                      bool find_all) {
    if ((!pattern && !signature) || (pattern && signature)) {
        throw PCILeechError("Either pattern or signature must be provided (not both)");
    }

    std::vector<string> args = {"search"};
    std::optional<string> working_directory;

    if (pattern) {
        utils::validate_hex_data(*pattern, "pattern");
        args.push_back("-in");
        args.push_back(*pattern);
    } else if (signature) {
        string safe_sig = utils::sanitize_path_component(*signature, "signature");
        auto sig_path = find_resource_file(fs::path(safe_sig + ".sig"), true);
        if (!sig_path) {
            throw SignatureNotFoundError("Signature file not found: " + safe_sig + ".sig");
        }
        args.push_back("-sig");
        args.push_back(safe_sig);
        working_directory = sig_path->parent_path().string();
    }

    if (min_addr) {
        args.push_back("-min");
        args.push_back(*min_addr);
    }

    if (max_addr) {
        args.push_back("-max");
        args.push_back(*max_addr);
    }

    if (find_all) {
        args.push_back("-all");
    }

    auto result = run_command(args, working_directory);

    if (result.return_code != 0 && result.return_code != 1) {
        throw PCILeechError("Memory search failed");
    }

    return parse_search_output("");
}

MemoryPatchResult PCILeechWrapper::patch_memory(const string& signature,
                                              std::optional<string> min_addr,
                                              std::optional<string> max_addr,
                                              bool patch_all) {
    string safe_sig = utils::sanitize_path_component(signature, "signature");
    auto sig_path = find_resource_file(fs::path(safe_sig + ".sig"), true);
    if (!sig_path) {
        throw SignatureNotFoundError("Signature file not found: " + safe_sig + ".sig");
    }

    std::vector<string> args = {"patch", "-sig", safe_sig};

    if (min_addr) {
        args.push_back("-min");
        args.push_back(*min_addr);
    }

    if (max_addr) {
        args.push_back("-max");
        args.push_back(*max_addr);
    }

    if (patch_all) {
        args.push_back("-all");
    }

    auto result = run_command(args, sig_path->parent_path().string());

    if (result.return_code != 0) {
        throw MemoryAccessError("Memory patch failed");
    }

    MemoryPatchResult patch_result;
    patch_result.signature = signature;
    patch_result.success = true;
    patch_result.output = "";

    return patch_result;
}

std::vector<ProcessInfo> PCILeechWrapper::list_processes() {
    auto result = run_command({"pslist"});

    if (result.return_code != 0) {
        throw PCILeechError("Process list failed");
    }

    return parse_pslist_output("");
}

TranslationResult PCILeechWrapper::translate_phys2virt(const string& phys_addr, const string& cr3) {
    uint64_t phys = utils::parse_hex_address(phys_addr, "physical_address");
    uint64_t cr3_val = utils::parse_hex_address(cr3, "cr3");

    std::vector<string> args = {
        "pt_phys2virt",
        "-cr3", "0x" + utils::uint64_to_hex(cr3_val, false),
        "-0", "0x" + utils::uint64_to_hex(phys, false)
    };

    auto result = run_command(args);

    TranslationResult trans_result;
    trans_result.physical = phys;
    trans_result.cr3 = cr3_val;
    trans_result.success = (result.return_code == 0);
    trans_result.output = "";

    return trans_result;
}

TranslationResult PCILeechWrapper::translate_virt2phys(const string& virt_addr, const string& cr3) {
    uint64_t virt = utils::parse_hex_address(virt_addr, "virtual_address");
    uint64_t cr3_val = utils::parse_hex_address(cr3, "cr3");

    std::vector<string> args = {
        "pt_virt2phys",
        "-cr3", "0x" + utils::uint64_to_hex(cr3_val, false),
        "-0", "0x" + utils::uint64_to_hex(virt, false)
    };

    auto result = run_command(args);

    TranslationResult trans_result;
    trans_result.virtual_addr = virt;
    trans_result.cr3 = cr3_val;
    trans_result.success = (result.return_code == 0);
    trans_result.output = "";

    return trans_result;
}

ProcessTranslationResult PCILeechWrapper::process_virt2phys(uint32_t pid, const string& virt_addr) {
    if (pid == 0) {
        throw PCILeechError("pid must be positive");
    }

    uint64_t virt = utils::parse_hex_address(virt_addr, "virtual_address");

    std::vector<string> args = {
        "psvirt2phys",
        "-0", std::to_string(pid),
        "-1", "0x" + utils::uint64_to_hex(virt, false)
    };

    auto result = run_command(args);

    ProcessTranslationResult trans_result;
    trans_result.pid = pid;
    trans_result.virtual_addr = virt;
    trans_result.success = (result.return_code == 0);
    trans_result.output = "";

    return trans_result;
}

KMDLoadResult PCILeechWrapper::load_kmd(const string& kmd_type, bool use_pt,
                                       std::optional<string> cr3, std::optional<string> sysmap) {
    std::vector<string> args = {"kmdload", "-kmd", kmd_type};

    if (use_pt) {
        args.push_back("-pt");
    }

    if (cr3) {
        uint64_t cr3_val = utils::parse_hex_address(*cr3, "cr3");
        args.push_back("-cr3");
        args.push_back("0x" + utils::uint64_to_hex(cr3_val, false));
    }

    if (sysmap) {
        args.push_back("-in");
        args.push_back(*sysmap);
    }

    auto result = run_command(args);

    KMDLoadResult load_result;
    load_result.kmd_type = kmd_type;
    load_result.success = (result.return_code == 0);
    load_result.output = "";

    if (load_result.success) {
        kmd_address_ = "";
        kmd_type_ = kmd_type;
    }

    return load_result;
}

KMDUnloadResult PCILeechWrapper::unload_kmd(std::optional<string> kmd_address) {
    string addr = kmd_address.value_or(kmd_address_.value_or(""));
    if (addr.empty()) {
        throw KMDError("No KMD address provided and no KMD currently loaded");
    }

    uint64_t addr_val = utils::parse_hex_address(addr, "kmd_address");

    std::vector<string> args = {
        "kmdexit",
        "-kmd", "0x" + utils::uint64_to_hex(addr_val, false)
    };

    auto result = run_command(args);

    KMDUnloadResult unload_result;
    unload_result.kmd_address = "0x" + utils::uint64_to_hex(addr_val, false);
    unload_result.success = (result.return_code == 0);
    unload_result.output = "";

    if (unload_result.success) {
        kmd_address_.reset();
        kmd_type_.reset();
    }

    return unload_result;
}

KSHExecuteResult PCILeechWrapper::execute_ksh(const string& script_name,
                                            std::optional<string> kmd_address,
                                            std::optional<string> input_file,
                                            std::optional<string> output_file,
                                            std::optional<string> string_param,
                                            std::optional<std::unordered_map<string, string>> numeric_params) {
    string addr = kmd_address.value_or(kmd_address_.value_or(""));
    if (addr.empty()) {
        throw KMDError("No KMD address provided and no KMD currently loaded");
    }

    string safe_script = utils::sanitize_path_component(script_name, "script_name");
    auto script_path = find_resource_file(fs::path(safe_script + ".ksh"), true);
    if (!script_path) {
        throw PCILeechError("Script file not found: " + safe_script + ".ksh");
    }

    uint64_t addr_val = utils::parse_hex_address(addr, "kmd_address");

    std::vector<string> args = {
        safe_script,
        "-kmd", "0x" + utils::uint64_to_hex(addr_val, false)
    };

    if (input_file) {
        args.push_back("-in");
        args.push_back(*input_file);
    }

    if (output_file) {
        args.push_back("-out");
        args.push_back(*output_file);
    }

    if (string_param) {
        args.push_back("-s");
        args.push_back(*string_param);
    }

    if (numeric_params) {
        for (const auto& [key, value] : *numeric_params) {
            try {
                int param_num = std::stoi(key);
                if (param_num >= 0 && param_num <= 9) {
                    args.push_back("-" + key);
                    args.push_back(value);
                }
            } catch (...) {
            }
        }
    }

    auto result = run_command(args, script_path->parent_path().string());

    KSHExecuteResult exec_result;
    exec_result.script = script_name;
    exec_result.kmd_address = "0x" + utils::uint64_to_hex(addr_val, false);
    exec_result.success = (result.return_code == 0);
    exec_result.output = "";

    return exec_result;
}

std::vector<KernelScript> PCILeechWrapper::list_available_scripts(const string& platform) {
    string exe_dir = utils::get_executable_directory();
    std::vector<KernelScript> scripts;

    return scripts;
}

BenchmarkResult PCILeechWrapper::run_benchmark(const string& test_type, const string& address) {
    uint64_t addr = utils::parse_hex_address(address);

    std::vector<string> args;
    if (test_type == "full") {
        args = {"benchmark"};
    } else if (test_type == "readwrite") {
        args = {"testmemreadwrite", "-min", "0x" + utils::uint64_to_hex(addr, false)};
    } else {
        args = {"testmemread", "-min", "0x" + utils::uint64_to_hex(addr, false)};
    }

    auto result = run_command(args);

    BenchmarkResult bench_result;
    bench_result.test_type = test_type;
    bench_result.address = "0x" + utils::uint64_to_hex(addr, false);
    bench_result.success = (result.return_code == 0);
    bench_result.output = "";

    return bench_result;
}

TLPResult PCILeechWrapper::send_tlp(std::optional<string> tlp_data, double wait_seconds, bool verbose) {
    std::vector<string> args = {"tlp"};

    if (tlp_data) {
        utils::validate_hex_data(*tlp_data, "tlp_data");
        args.push_back("-in");
        args.push_back(*tlp_data);
    }

    args.push_back("-wait");
    args.push_back(std::to_string(static_cast<int>(wait_seconds * 1000)));

    if (verbose) {
        args.push_back("-vv");
    }

    auto result = run_command(args);

    TLPResult tlp_result;
    tlp_result.success = (result.return_code == 0);
    if (tlp_data) {
        tlp_result.tlp_sent = *tlp_data;
    }
    tlp_result.wait_seconds = wait_seconds;
    tlp_result.output = "";

    return tlp_result;
}

FPGAConfigResult PCILeechWrapper::fpga_config(const string& action,
                                            std::optional<string> address,
                                            std::optional<string> data,
                                            std::optional<string> output_file) {
    if (action == "write" && !data) {
        throw PCILeechError("FPGA config write action requires data parameter");
    }

    std::vector<string> args = {"regcfg"};

    if (address) {
        uint64_t addr = utils::parse_hex_address(*address, "address");
        args.push_back("-min");
        args.push_back("0x" + utils::uint64_to_hex(addr, false));
    }

    if (action == "write" && data) {
        utils::validate_hex_data(*data, "data");
        args.push_back("-in");
        args.push_back(*data);
    }

    if (output_file) {
        args.push_back("-out");
        args.push_back(*output_file);
    }

    auto result = run_command(args);

    FPGAConfigResult config_result;
    config_result.action = action;
    if (address) {
        config_result.address = *address;
    }
    config_result.success = (result.return_code == 0);
    config_result.output = "";

    return config_result;
}

utils::CommandResult PCILeechWrapper::run_command(const std::vector<string>& args,
                                                  std::optional<string> working_directory) {
    std::vector<string> full_args;
    full_args.reserve(args.size() + 1);

    full_args.push_back(config_.get_absolute_executable_path());
    full_args.insert(full_args.end(), args.begin(), args.end());

    if (!working_directory) {
        try {
            fs::path exe = fs::path(full_args.front());
            if (!exe.empty() && exe.has_parent_path()) {
                working_directory = exe.parent_path().string();
            }
        } catch (...) {
        }
    }

    return utils::execute_command(full_args,
                                 config_.get_pcileech_config().timeout_seconds,
                                 working_directory);
}

string PCILeechWrapper::parse_display_output(const string& output) const {
    std::string hex_data;
    std::vector<string> lines = utils::split_lines(output);

    for (const string& line : lines) {
        if (line.empty() || line.find("Memory Display:") != string::npos ||
            line.find("Contents for address:") != string::npos) {
            continue;
        }

        string trimmed = utils::trim(line);
        if (trimmed.empty()) continue;

        std::regex offset_pattern(R"(^[0-9a-fA-F]{4,}\s+)");
        std::smatch match;
        if (std::regex_search(trimmed, match, offset_pattern)) {
            string hex_part = trimmed.substr(match[0].length());

            std::regex hex_byte_pattern(R"([0-9a-fA-F]{2})");
            auto begin = std::sregex_iterator(hex_part.begin(), hex_part.end(), hex_byte_pattern);
            auto end = std::sregex_iterator();

            for (std::sregex_iterator i = begin; i != end; ++i) {
                hex_data += (*i).str();
            }
        }
    }

    return hex_data;
}

SystemInfo PCILeechWrapper::parse_info_output(const string& output) const {
    SystemInfo info;
    info.raw_output = output;

    std::vector<string> lines = utils::split_lines(output);

    for (const string& line : lines) {
        string lower = utils::to_lower(line);

        if (lower.find("device:") != string::npos || lower.find("type:") != string::npos) {
            auto parts = utils::split(line, ':');
            if (parts.size() > 1) {
                info.device = utils::trim(parts[1]);
            }
        }

        if (lower.find("fpga") != string::npos) {
            info.fpga = true;
        }

        if ((lower.find("memory") != string::npos || lower.find("max") != string::npos) &&
            lower.find("size") != string::npos) {
            std::regex hex_pattern(R"(0x[0-9a-fA-F]+)");
            std::smatch match;
            if (std::regex_search(line, match, hex_pattern)) {
                info.memory_max = match.str();
            }
        }
    }

    return info;
}

std::vector<MemoryRegion> PCILeechWrapper::parse_probe_output(const string& output) const {
    std::vector<MemoryRegion> regions;
    std::vector<string> lines = utils::split_lines(output);

    for (const string& line : lines) {
        std::regex range_pattern(R"((0x[0-9a-fA-F]+)\s*[-:]\s*(0x[0-9a-fA-F]+).*?(OK|FAIL|readable|writable))",
                                std::regex_constants::icase);
        std::smatch match;

        if (std::regex_search(line, match, range_pattern)) {
            try {
                uint64_t start = utils::hex_to_uint64(match[1].str());
                uint64_t end = utils::hex_to_uint64(match[2].str());
                string status = utils::to_lower(match[3].str());

                MemoryRegion region;
                region.start = start;
                region.end = end;
                region.size = end - start;
                region.size_mb = static_cast<double>(region.size) / (1024.0 * 1024.0);
                region.status = (status == "ok") ? "readable" : status;

                regions.push_back(region);
            } catch (...) {
            }
        }
    }

    return regions;
}

std::vector<SearchMatch> PCILeechWrapper::parse_search_output(const string& output) const {
    std::vector<SearchMatch> matches;
    std::vector<string> lines = utils::split_lines(output);

    for (const string& line : lines) {
        std::regex addr_pattern(R"(match|found|at)?\s*(0x[0-9a-fA-F]+)", std::regex_constants::icase);
        std::smatch match;

        if (std::regex_search(line, match, addr_pattern) &&
            utils::to_lower(line).find("search") == string::npos) {
            SearchMatch search_match;
            search_match.address = utils::hex_to_uint64(match[2].str());
            search_match.line = utils::trim(line);
            matches.push_back(search_match);
        }
    }

    return matches;
}

std::vector<ProcessInfo> PCILeechWrapper::parse_pslist_output(const string& output) const {
    std::vector<ProcessInfo> processes;
    std::vector<string> lines = utils::split_lines(output);

    bool in_data = false;

    for (const string& line : lines) {
        string trimmed = utils::trim(line);
        if (trimmed.empty()) continue;

        string lower = utils::to_lower(trimmed);
        if (lower.find("pid") != string::npos && lower.find("name") != string::npos) {
            in_data = true;
            continue;
        }

        if (!in_data) {
            if (std::regex_match(trimmed, std::regex(R"(^\s*\d+\s+.*)"))) {
                in_data = true;
            } else {
                continue;
            }
        }

        auto parts = utils::split(trimmed);
        if (parts.size() >= 2) {
            try {
                uint32_t pid = static_cast<uint32_t>(std::stoul(parts[0]));

                ProcessInfo proc;
                proc.pid = pid;

                if (parts.size() >= 3) {
                    try {
                        proc.ppid = static_cast<uint32_t>(std::stoul(parts[1]));
                        proc.name = utils::join(std::vector<string>(parts.begin() + 2, parts.end()), " ");
                    } catch (...) {
                        proc.name = utils::join(std::vector<string>(parts.begin() + 1, parts.end()), " ");
                    }
                } else {
                    proc.name = parts[1];
                }

                processes.push_back(proc);
            } catch (...) {
            }
        }
    }

    return processes;
}

MemoryData PCILeechWrapper::read_memory_chunked(const string& address, size_t length,
                                              std::optional<uint32_t> pid,
                                              std::optional<string> process_name) {
    MemoryData all_data;
    uint64_t addr = utils::parse_hex_address(address);
    size_t bytes_remaining = length;
    uint64_t current_addr = addr;

    const size_t DISPLAY_SIZE = 256;
    const size_t ALIGN_SIZE = 16;

    while (bytes_remaining > 0) {
        uint64_t aligned_addr = (current_addr / ALIGN_SIZE) * ALIGN_SIZE;

        MemoryData chunk = read_single_chunk(aligned_addr, DISPLAY_SIZE, pid, process_name);
        if (chunk.empty()) {
            throw MemoryAccessError("Failed to read memory chunk at 0x" +
                                  utils::uint64_to_hex(aligned_addr));
        }

        size_t offset_in_chunk = current_addr - aligned_addr;
        size_t bytes_from_chunk = std::min(DISPLAY_SIZE - offset_in_chunk, bytes_remaining);

        all_data.insert(all_data.end(),
                       chunk.begin() + offset_in_chunk,
                       chunk.begin() + offset_in_chunk + bytes_from_chunk);

        bytes_remaining -= bytes_from_chunk;
        current_addr += bytes_from_chunk;
    }

    return all_data;
}

MemoryData PCILeechWrapper::read_single_chunk(uint64_t aligned_addr, size_t display_size,
                                            std::optional<uint32_t> pid,
                                            std::optional<string> process_name) {
    auto args = build_memory_args("display", "0x" + utils::uint64_to_hex(aligned_addr, false),
                                 pid, process_name);

    auto result = run_command(args);

    if (result.return_code != 0) {
        throw MemoryAccessError("Memory read failed with exit code " + std::to_string(result.return_code));
    }

    string hex_data = parse_display_output("");
    if (hex_data.empty()) {
        throw MemoryAccessError("No hex data returned from PCILeech display command");
    }

    MemoryData data = utils::hex_to_bytes(hex_data);

    if (data.size() != display_size) {
        throw MemoryAccessError("Expected " + std::to_string(display_size) + " bytes, got " +
                              std::to_string(data.size()));
    }

    return data;
}

std::vector<string> PCILeechWrapper::build_memory_args(const string& command, const string& address,
                                                     std::optional<uint32_t> pid,
                                                     std::optional<string> process_name) const {
    std::vector<string> args = {command};

    if (pid) {
        args.push_back("-pid");
        args.push_back(std::to_string(*pid));
        args.push_back("-vamin");
        args.push_back(address);
    } else if (process_name) {
        args.push_back("-psname");
        args.push_back(*process_name);
        args.push_back("-vamin");
        args.push_back(address);
    } else {
        args.push_back("-min");
        args.push_back(address);
    }

    return args;
}

std::vector<string> PCILeechWrapper::build_kmd_args(const string& kmd_addr) const {
    return {"-kmd", kmd_addr};
}

}
