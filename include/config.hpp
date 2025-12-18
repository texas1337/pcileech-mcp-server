#pragma once

#include "types.hpp"
#include <filesystem>

namespace mcp_server_pcileech {

class Config {
public:
    struct PCILeechConfig {
        string executable_path;
        int timeout_seconds;

        json to_json() const;
        static PCILeechConfig from_json(const json& j);
    };

    struct ServerConfig {
        string name;
        string version;

        json to_json() const;
        static ServerConfig from_json(const json& j);
    };

    Config();
    explicit Config(const string& config_path);

    bool load_from_file(const string& config_path);

    const PCILeechConfig& get_pcileech_config() const { return pcileech_; }
    const ServerConfig& get_server_config() const { return server_; }

    string get_absolute_executable_path() const;

    bool validate() const;

    static string get_default_config_path();

private:
    PCILeechConfig pcileech_;
    ServerConfig server_;
    string config_path_;

    static constexpr const char* DEFAULT_EXECUTABLE_PATH = "pcileech.exe";
    static constexpr int DEFAULT_TIMEOUT_SECONDS = 30;
    static constexpr const char* DEFAULT_SERVER_NAME = "mcp-server-pcileech";
    static constexpr const char* DEFAULT_SERVER_VERSION = "1.0.0";
};

}
