#include "gui_manager.hpp"
#include <stdexcept>

GUIManager::GUIManager(HINSTANCE hInstance, MCPServer* server)
    : hInstance_(hInstance)
    , server_(server)
    , hwnd_(NULL)
    , hFont_(NULL)
    , dmaWorking_(false) {
}

GUIManager::~GUIManager() {
    shutdown();
}

bool GUIManager::initialize() {
    if (!createWindow()) return false;

    hFont_ = CreateFont(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                       DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                       DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");

    ShowWindow(hwnd_, SW_SHOW);
    UpdateWindow(hwnd_);

    return true;
}

void GUIManager::run() {
    MSG msg = {};
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
}

void GUIManager::shutdown() {
    if (hFont_) {
        DeleteObject(hFont_);
        hFont_ = NULL;
    }
    if (hwnd_) {
        DestroyWindow(hwnd_);
        hwnd_ = NULL;
    }
}

bool GUIManager::createWindow() {
    WNDCLASSEX wc = {};
    wc.cbSize = sizeof(WNDCLASSEX);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance_;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = WINDOW_CLASS_NAME;

    if (!RegisterClassEx(&wc)) return false;

    RECT rc = { 0, 0, WINDOW_WIDTH, WINDOW_HEIGHT };
    AdjustWindowRect(&rc, WS_OVERLAPPEDWINDOW, FALSE);

    hwnd_ = CreateWindowEx(
        0,
        WINDOW_CLASS_NAME,
        WINDOW_TITLE,
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        rc.right - rc.left, rc.bottom - rc.top,
        NULL, NULL, hInstance_, this
    );

    return hwnd_ != NULL;
}

void GUIManager::updateDeviceStatus() {
    devices_.clear();

    DeviceInfo device;
    device.name = "PCILeech FPGA Device";
    device.connected = dmaWorking_;
    device.status = dmaWorking_ ? "Connected" : "Disconnected";
    device.firmware_version = "v4.15";
    device.memory_size = 8ULL * 1024 * 1024 * 1024;

    devices_.push_back(device);

    dmaWorking_ = server_->isDMAWorking();
}

void GUIManager::drawInterface(HDC hdc) {
    updateDeviceStatus();

    drawDevicePanel(hdc);
    drawDMAPanel(hdc);
    drawMemoryPanel(hdc);
    drawStatusBar(hdc);
}

void GUIManager::drawDevicePanel(HDC hdc) {
    SelectObject(hdc, hFont_);

    int y = 50;
    for (const auto& device : devices_) {
        std::string status = device.name + " - " + device.status;

        RECT rect = { 50, y, 400, y + 30 };

        if (device.connected) {
            SetBkColor(hdc, RGB(0, 255, 0));
            SetTextColor(hdc, RGB(0, 0, 0));
        } else {
            SetBkColor(hdc, RGB(255, 0, 0));
            SetTextColor(hdc, RGB(255, 255, 255));
        }

        DrawTextA(hdc, status.c_str(), -1, &rect, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        y += 40;
    }
}

void GUIManager::drawDMAPanel(HDC hdc) {
    std::string dmaStatus = "DMA Status: " + std::string(dmaWorking_ ? "WORKING" : "NOT WORKING");

    RECT rect = { 450, 50, 700, 100 };

    if (dmaWorking_) {
        SetBkColor(hdc, RGB(0, 255, 0));
        SetTextColor(hdc, RGB(0, 0, 0));
    } else {
        SetBkColor(hdc, RGB(255, 0, 0));
        SetTextColor(hdc, RGB(255, 255, 255));
    }

    DrawTextA(hdc, dmaStatus.c_str(), -1, &rect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
}

void GUIManager::drawMemoryPanel(HDC hdc) {
    std::string memInfo = "Memory Operations Panel";

    RECT rect = { 50, 200, 400, 250 };
    SetBkColor(hdc, RGB(0, 0, 255));
    SetTextColor(hdc, RGB(255, 255, 255));

    DrawTextA(hdc, memInfo.c_str(), -1, &rect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

    std::string recentOps = "Recent Operations: " + std::to_string(recentOperations_.size());
    RECT opsRect = { 50, 260, 400, 310 };
    SetBkColor(hdc, RGB(200, 200, 200));
    SetTextColor(hdc, RGB(0, 0, 0));

    DrawTextA(hdc, recentOps.c_str(), -1, &opsRect, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
}

void GUIManager::drawStatusBar(HDC hdc) {
    std::string status = "PCILeech GUI Manager - Ready";

    RECT rect = { 0, WINDOW_HEIGHT - 50, WINDOW_WIDTH, WINDOW_HEIGHT };
    SetBkColor(hdc, RGB(100, 100, 100));
    SetTextColor(hdc, RGB(255, 255, 255));

    DrawTextA(hdc, status.c_str(), -1, &rect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
}

LRESULT CALLBACK GUIManager::WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    GUIManager* pThis = nullptr;

    if (uMsg == WM_NCCREATE) {
        CREATESTRUCT* pCreate = (CREATESTRUCT*)lParam;
        pThis = (GUIManager*)pCreate->lpCreateParams;
        SetWindowLongPtr(hwnd, GWLP_USERDATA, (LONG_PTR)pThis);
        pThis->hwnd_ = hwnd;
    } else {
        pThis = (GUIManager*)GetWindowLongPtr(hwnd, GWLP_USERDATA);
    }

    if (pThis) {
        switch (uMsg) {
            case WM_DESTROY:
                PostQuitMessage(0);
                return 0;
            case WM_PAINT: {
                PAINTSTRUCT ps;
                HDC hdc = BeginPaint(hwnd, &ps);
                pThis->drawInterface(hdc);
                EndPaint(hwnd, &ps);
                return 0;
            }
            case WM_TIMER:
                InvalidateRect(hwnd, NULL, TRUE);
                return 0;
            case WM_CREATE:
                SetTimer(hwnd, 1, 1000, NULL);
                return 0;
        }
    }

    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}
