#include "config.hpp"
#include "utils.hpp"
#include <filesystem>
#include <fstream>

namespace mcp_server_pcileech {
namespace fs = std::filesystem;

static fs::path get_app_dir_path() {
    try {
        return fs::path(utils::get_executable_directory());
    } catch (...) {
        return fs::current_path();
    }
}

static fs::path resolve_config_path(const string& config_path) {
    fs::path p(config_path);
    if (p.is_absolute()) {
        return p;
    }

    fs::path cwd_candidate = fs::absolute(p);
    if (fs::exists(cwd_candidate)) {
        return cwd_candidate;
    }

    fs::path app_candidate = get_app_dir_path() / p;
    if (fs::exists(app_candidate)) {
        return app_candidate;
    }

    return app_candidate;
}

static fs::path resolve_pcileech_executable(const fs::path& config_dir,
                                            const fs::path& app_dir,
                                            const fs::path& configured_path) {
    std::vector<fs::path> candidates;

    if (configured_path.is_absolute()) {
        candidates.push_back(configured_path);
    } else {
        candidates.push_back(config_dir / configured_path);
        if (!app_dir.empty() && app_dir != config_dir) {
            candidates.push_back(app_dir / configured_path);
        }
    }

    for (const auto& base : {config_dir, app_dir}) {
        if (base.empty()) continue;
        candidates.push_back(base / "pcileech.exe");
        candidates.push_back(base / "bin" / "pcileech.exe");
        candidates.push_back(base / "pcileech" / "pcileech.exe");
    }

    fs::path cur = app_dir.empty() ? config_dir : app_dir;
    for (int i = 0; i < 6 && !cur.empty(); ++i) {
        candidates.push_back(cur / "bin" / "pcileech.exe");
        candidates.push_back(cur / "pcileech.exe");
        auto parent = cur.parent_path();
        if (parent == cur) break;
        cur = parent;
    }

    fs::path current_exe_path;
    try {
        current_exe_path = fs::path(utils::get_current_executable_path());
    } catch (...) {}

    for (const auto& c : candidates) {
        std::error_code ec;
        if (!c.empty() && fs::exists(c, ec) && !ec) {
            if (!current_exe_path.empty()) {
                std::error_code ec2;
                if (fs::equivalent(c, current_exe_path, ec2)) {
                    continue;
                }
            }
            return c.lexically_normal();
        }
    }

    fs::path fallback = candidates.empty() ? configured_path : candidates.front().lexically_normal();
    if (!current_exe_path.empty()) {
        std::error_code ec2;
        if (!fallback.empty() && fs::equivalent(fallback, current_exe_path, ec2) && !ec2) {
            return fs::path();
        }
    }
    return fallback;
}

Config::Config() : Config(get_default_config_path()) {}

Config::Config(const string& config_path) : config_path_(resolve_config_path(config_path).string()) {
    pcileech_.executable_path = DEFAULT_EXECUTABLE_PATH;
    pcileech_.timeout_seconds = DEFAULT_TIMEOUT_SECONDS;
    server_.name = DEFAULT_SERVER_NAME;
    server_.version = DEFAULT_SERVER_VERSION;

    try {
        (void)load_from_file(config_path_);
    } catch (const ConfigError&) {
    }
}

bool Config::load_from_file(const string& config_path) {
    std::ifstream file(config_path);
    if (!file.is_open()) {
        return false;
    }

    try {
        json j;
        file >> j;

        if (j.contains("pcileech")) {
            pcileech_ = PCILeechConfig::from_json(j["pcileech"]);
        }

        if (j.contains("server")) {
            server_ = ServerConfig::from_json(j["server"]);
        }

        config_path_ = config_path;
        return true;
    } catch (const std::exception& e) {
        throw ConfigError("Error reading config file '" + config_path + "': " + string(e.what()));
    }
}

string Config::get_absolute_executable_path() const {
    const fs::path configured = fs::path(pcileech_.executable_path);
    const fs::path config_dir = fs::path(config_path_).parent_path();
    const fs::path app_dir = get_app_dir_path();

    return resolve_pcileech_executable(config_dir, app_dir, configured).string();
}

bool Config::validate() const {
    if (!utils::path_exists(get_absolute_executable_path())) {
        return false;
    }

    if (pcileech_.timeout_seconds <= 0 || pcileech_.timeout_seconds > 300) {
        return false;
    }

    return true;
}

string Config::get_default_config_path() {
    return (get_app_dir_path() / "config.json").string();
}

json Config::PCILeechConfig::to_json() const {
    return {
        {"executable_path", executable_path},
        {"timeout_seconds", timeout_seconds}
    };
}

Config::PCILeechConfig Config::PCILeechConfig::from_json(const json& j) {
    return {
        j.value("executable_path", DEFAULT_EXECUTABLE_PATH),
        j.value("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)
    };
}

json Config::ServerConfig::to_json() const {
    return {
        {"name", name},
        {"version", version}
    };
}

Config::ServerConfig Config::ServerConfig::from_json(const json& j) {
    return {
        j.value("name", DEFAULT_SERVER_NAME),
        j.value("version", DEFAULT_SERVER_VERSION)
    };
}

}