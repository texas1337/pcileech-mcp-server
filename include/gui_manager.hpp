#pragma once

#include "mcp_server.hpp"
#include <windows.h>
#include <string>
#include <vector>

struct DeviceInfo {
    std::string name;
    std::string status;
    bool connected;
    std::string firmware_version;
    uint64_t memory_size;
};

struct DMAOperation {
    std::string type;
    std::string address;
    size_t size;
    bool success;
    double duration_ms;
};

class GUIManager {
public:
    GUIManager(HINSTANCE hInstance, MCPServer* server);
    ~GUIManager();

    bool initialize();
    void run();
    void shutdown();

private:
    static LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

    bool createWindow();
    void updateDeviceStatus();
    void drawInterface(HDC hdc);

    void drawDevicePanel(HDC hdc);
    void drawDMAPanel(HDC hdc);
    void drawMemoryPanel(HDC hdc);
    void drawStatusBar(HDC hdc);

    HINSTANCE hInstance_;
    MCPServer* server_;
    HWND hwnd_;
    HFONT hFont_;

    std::vector<DeviceInfo> devices_;
    std::vector<DMAOperation> recentOperations_;
    bool dmaWorking_;

    static constexpr int WINDOW_WIDTH = 1000;
    static constexpr int WINDOW_HEIGHT = 700;
    static constexpr const char* WINDOW_CLASS_NAME = "PCILeechGUI";
    static constexpr const char* WINDOW_TITLE = "PCILeech DMA Manager";
};
