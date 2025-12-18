#pragma once

#include "types.hpp"
#include "config.hpp"
#include "memory_formatter.hpp"
#include "utils.hpp"
#include <mutex>
#include <atomic>

namespace mcp_server_pcileech {

class PCILeechWrapper {
public:
    explicit PCILeechWrapper(const Config& config);
    ~PCILeechWrapper() = default;

    PCILeechWrapper(const PCILeechWrapper&) = delete;
    PCILeechWrapper& operator=(const PCILeechWrapper&) = delete;
    PCILeechWrapper(PCILeechWrapper&&) = delete;
    PCILeechWrapper& operator=(PCILeechWrapper&&) = delete;

    bool verify_connection();
    MemoryData read_memory(const string& address, size_t length,
                          std::optional<uint32_t> pid = std::nullopt,
                          std::optional<string> process_name = std::nullopt);

    bool write_memory(const string& address, const MemoryData& data,
                     std::optional<uint32_t> pid = std::nullopt,
                     std::optional<string> process_name = std::nullopt);

    MemoryFormatter::MemoryViews format_memory(const string& address, size_t length,
                            const std::vector<string>& formats,
                            std::optional<uint32_t> pid = std::nullopt,
                            std::optional<string> process_name = std::nullopt);

    SystemInfo get_system_info(bool verbose = false);
    std::vector<MemoryRegion> probe_memory(const string& min_addr = "0x0",
                                         std::optional<string> max_addr = std::nullopt);
    MemoryDumpResult dump_memory(const string& min_addr, const string& max_addr,
                               std::optional<string> output_file = std::nullopt,
                               bool force = false);
    std::vector<SearchMatch> search_memory(std::optional<string> pattern = std::nullopt,
                                         std::optional<string> signature = std::nullopt,
                                         std::optional<string> min_addr = std::nullopt,
                                         std::optional<string> max_addr = std::nullopt,
                                         bool find_all = false);
    MemoryPatchResult patch_memory(const string& signature,
                                 std::optional<string> min_addr = std::nullopt,
                                 std::optional<string> max_addr = std::nullopt,
                                 bool patch_all = false);
    std::vector<ProcessInfo> list_processes();

    TranslationResult translate_phys2virt(const string& phys_addr, const string& cr3);
    TranslationResult translate_virt2phys(const string& virt_addr, const string& cr3);
    ProcessTranslationResult process_virt2phys(uint32_t pid, const string& virt_addr);

    KMDLoadResult load_kmd(const string& kmd_type, bool use_pt = false,
                          std::optional<string> cr3 = std::nullopt,
                          std::optional<string> sysmap = std::nullopt);
    KMDUnloadResult unload_kmd(std::optional<string> kmd_address = std::nullopt);
    KSHExecuteResult execute_ksh(const string& script_name,
                               std::optional<string> kmd_address = std::nullopt,
                               std::optional<string> input_file = std::nullopt,
                               std::optional<string> output_file = std::nullopt,
                               std::optional<string> string_param = std::nullopt,
                               std::optional<std::unordered_map<string, string>> numeric_params = std::nullopt);
    std::vector<KernelScript> list_available_scripts(const string& platform = "all");

    BenchmarkResult run_benchmark(const string& test_type = "read", const string& address = "0x1000");
    TLPResult send_tlp(std::optional<string> tlp_data = std::nullopt,
                     double wait_seconds = 0.5, bool verbose = true);
    FPGAConfigResult fpga_config(const string& action = "read",
                               std::optional<string> address = std::nullopt,
                               std::optional<string> data = std::nullopt,
                               std::optional<string> output_file = std::nullopt);

    bool is_kmd_loaded() const { return kmd_address_.has_value(); }
    std::optional<string> get_kmd_address() const { return kmd_address_; }
    std::optional<string> get_kmd_type() const { return kmd_type_; }

private:
    const Config& config_;
    std::optional<string> kmd_address_;
    std::optional<string> kmd_type_;
    mutable std::mutex kmd_mutex_;
    utils::CommandResult run_command(const std::vector<string>& args,
                                    std::optional<string> working_directory = std::nullopt);
    string parse_display_output(const string& output) const;
    SystemInfo parse_info_output(const string& output) const;
    std::vector<MemoryRegion> parse_probe_output(const string& output) const;
    std::vector<SearchMatch> parse_search_output(const string& output) const;
    std::vector<ProcessInfo> parse_pslist_output(const string& output) const;

    MemoryData read_memory_chunked(const string& address, size_t length,
                                 std::optional<uint32_t> pid,
                                 std::optional<string> process_name);
    MemoryData read_single_chunk(uint64_t aligned_addr, size_t display_size,
                               std::optional<uint32_t> pid,
                               std::optional<string> process_name);

    std::vector<string> build_memory_args(const string& command, const string& address,
                                        std::optional<uint32_t> pid,
                                        std::optional<string> process_name) const;
    std::vector<string> build_kmd_args(const string& kmd_addr) const;
};

}
