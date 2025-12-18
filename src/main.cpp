#define WIN32_LEAN_AND_MEAN
#ifndef _WIN32_IE
#define _WIN32_IE 0x0600
#endif
#include <windows.h>
#include <commctrl.h>
#include <dwmapi.h>
#include <setupapi.h>

#include "config.hpp"
#include "mcp_server.hpp"
#include "pcileech_wrapper.hpp"
#include "utils.hpp"

#include <atomic>
#include <filesystem>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <cwctype>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "setupapi.lib")

namespace mcp_server_pcileech {
namespace {

constexpr wchar_t kWindowClassName[] = L"mcp_server_pcileech_gui";
constexpr wchar_t kWindowTitle[] = L"PCILeech Control Panel";
constexpr wchar_t kDevicesWindowClassName[] = L"mcp_server_pcileech_devices";
constexpr wchar_t kDevicesWindowTitle[] = L"PCIe Device Manager";
constexpr wchar_t kDebugWindowClassName[] = L"mcp_server_pcileech_debug";
constexpr wchar_t kDebugWindowTitle[] = L"PCILeech Debug Manager";

constexpr UINT WM_APP_STATUS_RESULT = WM_APP + 1;
constexpr UINT WM_APP_COMMAND_RESULT = WM_APP + 2;
constexpr UINT_PTR TIMER_ID_STATUS = 1;
constexpr int ID_REFRESH = 1;
constexpr int ID_RUN = 2;
constexpr int ID_DEVICES = 3;
constexpr int ID_DEBUG = 4;
constexpr int ID_AUTO = 5;
static HWND g_devices_hwnd = nullptr;
static HWND g_debug_hwnd = nullptr;

struct StatusResultMsg {
    bool exe_found = false;
    bool dma_connected = false;
    bool dma_verified = false;
    int potential_dma_count = 0;
    std::string exe_path;
    std::string detail;
};

struct CommandResultMsg {
    std::string text;
};

struct AppState {
    HWND hwnd = nullptr;
    HWND label_exe = nullptr;
    HWND label_dma = nullptr;
    HWND progress_dma = nullptr;
    HWND btn_refresh = nullptr;
    HWND btn_devices = nullptr;
    HWND btn_debug = nullptr;
    HWND chk_auto = nullptr;
    HWND edit_command = nullptr;
    HWND btn_run = nullptr;
    HWND edit_log = nullptr;

    COLORREF color_bg = RGB(32, 32, 32);
    COLORREF color_edit = RGB(45, 45, 45);
    COLORREF color_text = RGB(230, 230, 230);
    HBRUSH brush_bg = nullptr;
    HBRUSH brush_edit = nullptr;

    std::unique_ptr<Config> config;
    bool auto_refresh = true;
    std::atomic<int> busy{0};
    std::atomic<ULONGLONG> busy_since{0};
    bool has_queued_command = false;
    std::string queued_command;

    bool last_exe_found = false;
    bool last_dma_connected = false;
    bool last_dma_verified = false;
    int last_potential_dma_count = 0;
    std::string last_exe_path;
    std::string last_status_detail;
    std::string last_command_detail;
};

static std::wstring utf8_to_wide(const std::string& s) {
    if (s.empty()) return L"";
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (len <= 0) return L"";
    std::wstring w(static_cast<size_t>(len), L'\0');
    if (MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, w.data(), len) == 0) return L"";
    if (!w.empty() && w.back() == L'\0') w.pop_back();
    return w;
}

static std::string wide_to_utf8(const std::wstring& w) {
    if (w.empty()) return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return "";
    std::string s(static_cast<size_t>(len), '\0');
    if (WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, s.data(), len, nullptr, nullptr) == 0) return "";
    if (!s.empty() && s.back() == '\0') s.pop_back();
    return s;
}

static void set_text(HWND hwnd, const std::string& text) {
    std::wstring w = utf8_to_wide(text);
    SetWindowTextW(hwnd, w.c_str());
}

static void append_log(HWND edit, const std::string& text) {
    std::wstring w = utf8_to_wide(text);
    const int len = GetWindowTextLengthW(edit);
    SendMessageW(edit, EM_SETSEL, len, len);
    SendMessageW(edit, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(w.c_str()));
    SendMessageW(edit, EM_SCROLLCARET, 0, 0);
}

static bool try_begin_op(AppState* st, int op) {
    if (!st) return false;
    int expected = 0;
    if (!st->busy.compare_exchange_strong(expected, op)) {
        return false;
    }
    st->busy_since = GetTickCount64();
    return true;
}

static void end_op(AppState* st) {
    if (!st) return;
    st->busy = 0;
    st->busy_since = 0;
}

static std::string get_edit_text(HWND edit) {
    if (!edit) return "";
    wchar_t buf[2048];
    GetWindowTextW(edit, buf, static_cast<int>(std::size(buf)));
    return wide_to_utf8(buf);
}

static void enable_dark_title_bar(HWND hwnd) {
    if (!hwnd) return;
    BOOL value = TRUE;
    const DWORD attr_new = 20;
    const DWORD attr_old = 19;
    if (FAILED(DwmSetWindowAttribute(hwnd, attr_new, &value, sizeof(value)))) {
        (void)DwmSetWindowAttribute(hwnd, attr_old, &value, sizeof(value));
    }
}

struct PciDeviceEntry {
    std::wstring description;
    std::wstring instance_id;
    std::wstring hardware_id;
    bool potential_dma = false;
};

static std::wstring upper_copy(const std::wstring& s) {
    std::wstring out = s;
    for (auto& ch : out) {
        ch = static_cast<wchar_t>(std::towupper(ch));
    }
    return out;
}

static bool contains_any(const std::wstring& hay, const std::initializer_list<const wchar_t*>& needles) {
    for (const wchar_t* n : needles) {
        if (n && *n && hay.find(n) != std::wstring::npos) {
            return true;
        }
    }
    return false;
}

static bool is_potential_dma_device(const PciDeviceEntry& d) {
    const std::wstring desc = upper_copy(d.description);
    const std::wstring inst = upper_copy(d.instance_id);
    const std::wstring hw = upper_copy(d.hardware_id);

    if (contains_any(desc, {L"PCILEECH", L"SCREAMER", L"SQUIRREL", L"FPGA", L"XDMA", L"DMA"})) return true;
    if (contains_any(inst, {L"PCILEECH", L"SCREAMER", L"SQUIRREL", L"FPGA", L"XDMA", L"DMA"})) return true;
    if (contains_any(hw, {L"VEN_10EE", L"VEN_1172", L"VEN_1204"})) return true;
    if (contains_any(hw, {L"PCILEECH", L"SCREAMER", L"SQUIRREL", L"FPGA", L"XDMA", L"DMA"})) return true;

    return false;
}

static std::wstring device_property_string(HDEVINFO info, SP_DEVINFO_DATA* dev, DWORD prop) {
    if (!info || info == INVALID_HANDLE_VALUE || !dev) return L"";
    DWORD reg_type = 0;
    DWORD required = 0;
    SetupDiGetDeviceRegistryPropertyW(info, dev, prop, &reg_type, nullptr, 0, &required);
    if (required == 0) return L"";
    std::vector<BYTE> buf(required);
    if (!SetupDiGetDeviceRegistryPropertyW(info, dev, prop, &reg_type, buf.data(), required, nullptr)) {
        return L"";
    }
    if (reg_type == REG_MULTI_SZ) {
        const wchar_t* p = reinterpret_cast<const wchar_t*>(buf.data());
        if (!p) return L"";
        return std::wstring(p);
    }
    const wchar_t* p = reinterpret_cast<const wchar_t*>(buf.data());
    if (!p) return L"";
    return std::wstring(p);
}

static std::wstring device_instance_id(HDEVINFO info, SP_DEVINFO_DATA* dev) {
    if (!info || info == INVALID_HANDLE_VALUE || !dev) return L"";
    DWORD required = 0;
    SetupDiGetDeviceInstanceIdW(info, dev, nullptr, 0, &required);
    if (required == 0) return L"";
    std::wstring buf(static_cast<size_t>(required), L'\0');
    if (!SetupDiGetDeviceInstanceIdW(info, dev, buf.data(), required, nullptr)) {
        return L"";
    }
    if (!buf.empty() && buf.back() == L'\0') buf.pop_back();
    return buf;
}

static std::vector<PciDeviceEntry> enumerate_pci_devices() {
    std::vector<PciDeviceEntry> out;
    HDEVINFO info = SetupDiGetClassDevsW(nullptr, L"PCI", nullptr, DIGCF_PRESENT | DIGCF_ALLCLASSES);
    if (info == INVALID_HANDLE_VALUE) {
        return out;
    }

    SP_DEVINFO_DATA dev = {};
    dev.cbSize = sizeof(dev);

    for (DWORD i = 0; SetupDiEnumDeviceInfo(info, i, &dev); ++i) {
        PciDeviceEntry e;
        e.instance_id = device_instance_id(info, &dev);
        e.description = device_property_string(info, &dev, SPDRP_FRIENDLYNAME);
        if (e.description.empty()) {
            e.description = device_property_string(info, &dev, SPDRP_DEVICEDESC);
        }
        e.hardware_id = device_property_string(info, &dev, SPDRP_HARDWAREID);
        e.potential_dma = is_potential_dma_device(e);
        if (e.description.empty() && e.instance_id.empty() && e.hardware_id.empty()) {
            continue;
        }
        out.push_back(std::move(e));
    }

    SetupDiDestroyDeviceInfoList(info);
    return out;
}

static int potential_dma_device_count() {
    const auto devs = enumerate_pci_devices();
    int count = 0;
    for (const auto& d : devs) {
        if (d.potential_dma) {
            ++count;
        }
    }
    return count;
}

struct DevicesState {
    HWND hwnd = nullptr;
    HWND list = nullptr;
    HWND btn_refresh = nullptr;
    COLORREF color_bg = RGB(32, 32, 32);
    COLORREF color_list_bg = RGB(45, 45, 45);
    COLORREF color_text = RGB(230, 230, 230);
    COLORREF color_dma = RGB(0, 220, 120);
    HBRUSH brush_bg = nullptr;
    std::vector<PciDeviceEntry> devices;
};

static DevicesState* get_devices_state(HWND hwnd) {
    return reinterpret_cast<DevicesState*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
}

static void devices_populate(DevicesState* st) {
    if (!st || !st->list) return;
    ListView_DeleteAllItems(st->list);
    st->devices = enumerate_pci_devices();
    int idx = 0;
    for (const auto& d : st->devices) {
        LVITEMW item = {};
        item.mask = LVIF_TEXT;
        item.iItem = idx;
        item.pszText = const_cast<wchar_t*>(d.description.c_str());
        const int row = ListView_InsertItem(st->list, &item);
        if (row >= 0) {
            ListView_SetItemText(st->list, row, 1, const_cast<wchar_t*>(d.instance_id.c_str()));
            ListView_SetItemText(st->list, row, 2, const_cast<wchar_t*>(d.hardware_id.c_str()));
            if (d.potential_dma) {
                ListView_SetItemText(st->list, row, 3, const_cast<wchar_t*>(L"YES"));
            }
        }
        ++idx;
    }
}

static LRESULT CALLBACK DevicesWndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
    DevicesState* st = get_devices_state(hwnd);
    switch (msg) {
        case WM_NCCREATE: {
            auto* cs = reinterpret_cast<CREATESTRUCTW*>(lparam);
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(cs->lpCreateParams));
            return DefWindowProcW(hwnd, msg, wparam, lparam);
        }
        case WM_CREATE: {
            st = get_devices_state(hwnd);
            if (!st) return -1;
            st->hwnd = hwnd;
            st->brush_bg = CreateSolidBrush(st->color_bg);
            enable_dark_title_bar(hwnd);

            const HFONT font = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));

            st->btn_refresh = CreateWindowW(L"BUTTON", L"Refresh", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                            12, 12, 100, 26, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(1)), nullptr, nullptr);

            st->list = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
                                       WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SHOWSELALWAYS,
                                       12, 48, 860, 500, hwnd, nullptr, nullptr, nullptr);

            SendMessageW(st->btn_refresh, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
            SendMessageW(st->list, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);

            ListView_SetExtendedListViewStyle(st->list, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
            ListView_SetBkColor(st->list, st->color_list_bg);
            ListView_SetTextBkColor(st->list, st->color_list_bg);
            ListView_SetTextColor(st->list, st->color_text);

            LVCOLUMNW col = {};
            col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
            col.pszText = const_cast<wchar_t*>(L"Description");
            col.cx = 260;
            ListView_InsertColumn(st->list, 0, &col);
            col.pszText = const_cast<wchar_t*>(L"Instance ID");
            col.cx = 340;
            col.iSubItem = 1;
            ListView_InsertColumn(st->list, 1, &col);
            col.pszText = const_cast<wchar_t*>(L"Hardware ID");
            col.cx = 240;
            col.iSubItem = 2;
            ListView_InsertColumn(st->list, 2, &col);
            col.pszText = const_cast<wchar_t*>(L"DMA");
            col.cx = 60;
            col.iSubItem = 3;
            ListView_InsertColumn(st->list, 3, &col);

            devices_populate(st);
            return 0;
        }
        case WM_ERASEBKGND: {
            if (!st || !st->brush_bg) return DefWindowProcW(hwnd, msg, wparam, lparam);
            RECT rc;
            GetClientRect(hwnd, &rc);
            FillRect(reinterpret_cast<HDC>(wparam), &rc, st->brush_bg);
            return 1;
        }
        case WM_CTLCOLORBTN:
        case WM_CTLCOLORSTATIC: {
            if (!st) return DefWindowProcW(hwnd, msg, wparam, lparam);
            const HDC hdc = reinterpret_cast<HDC>(wparam);
            SetTextColor(hdc, st->color_text);
            SetBkMode(hdc, OPAQUE);
            SetBkColor(hdc, st->color_bg);
            return reinterpret_cast<LRESULT>(st->brush_bg ? st->brush_bg : GetStockObject(BLACK_BRUSH));
        }
        case WM_NOTIFY: {
            if (!st) return 0;
            auto* hdr = reinterpret_cast<NMHDR*>(lparam);
            if (hdr && hdr->hwndFrom == st->list && hdr->code == NM_CUSTOMDRAW) {
                auto* cd = reinterpret_cast<NMLVCUSTOMDRAW*>(lparam);
                if (cd->nmcd.dwDrawStage == CDDS_PREPAINT) {
                    return CDRF_NOTIFYITEMDRAW;
                }
                if (cd->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) {
                    const int row = static_cast<int>(cd->nmcd.dwItemSpec);
                    cd->clrTextBk = st->color_list_bg;
                    if (row >= 0 && row < static_cast<int>(st->devices.size()) && st->devices[static_cast<size_t>(row)].potential_dma) {
                        cd->clrText = st->color_dma;
                    } else {
                        cd->clrText = st->color_text;
                    }
                    return CDRF_NEWFONT;
                }
            }
            return 0;
        }
        case WM_SIZE: {
            if (!st) return 0;
            RECT rc;
            GetClientRect(hwnd, &rc);
            const int width = rc.right - rc.left;
            const int height = rc.bottom - rc.top;
            const int top = 48;
            MoveWindow(st->list, 12, top, width - 24, height - top - 12, TRUE);
            return 0;
        }
        case WM_COMMAND: {
            const int id = LOWORD(wparam);
            if (id == 1 && st) {
                devices_populate(st);
                return 0;
            }
            return 0;
        }
        case WM_DESTROY: {
            if (st) {
                if (st->brush_bg) {
                    DeleteObject(st->brush_bg);
                    st->brush_bg = nullptr;
                }
            }
            g_devices_hwnd = nullptr;
            return 0;
        }
        case WM_NCDESTROY: {
            auto* p = get_devices_state(hwnd);
            if (p) {
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
                delete p;
            }
            return 0;
        }
        default:
            return DefWindowProcW(hwnd, msg, wparam, lparam);
    }
}

static void show_devices_window(HWND owner) {
    if (g_devices_hwnd && IsWindow(g_devices_hwnd)) {
        ShowWindow(g_devices_hwnd, SW_SHOW);
        SetForegroundWindow(g_devices_hwnd);
        return;
    }

    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = DevicesWndProc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = nullptr;
    wc.lpszClassName = kDevicesWindowClassName;
    RegisterClassExW(&wc);

    auto* st = new DevicesState();
    HWND hwnd = CreateWindowExW(0, kDevicesWindowClassName, kDevicesWindowTitle,
                                WS_OVERLAPPEDWINDOW,
                                CW_USEDEFAULT, CW_USEDEFAULT,
                                920, 620,
                                owner, nullptr, wc.hInstance, st);
    if (!hwnd) {
        delete st;
        return;
    }
    g_devices_hwnd = hwnd;
    if (!AnimateWindow(hwnd, 150, AW_BLEND | AW_ACTIVATE)) {
        ShowWindow(hwnd, SW_SHOW);
    }
    UpdateWindow(hwnd);
}

struct DebugState {
    AppState* app = nullptr;
    HWND hwnd = nullptr;
    HWND btn_refresh = nullptr;
    HWND btn_copy = nullptr;
    HWND edit = nullptr;
    COLORREF color_bg = RGB(32, 32, 32);
    COLORREF color_edit = RGB(45, 45, 45);
    COLORREF color_text = RGB(230, 230, 230);
    HBRUSH brush_bg = nullptr;
    HBRUSH brush_edit = nullptr;
};

static DebugState* get_debug_state(HWND hwnd) {
    return reinterpret_cast<DebugState*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
}

static void debug_set_text(DebugState* st) {
    if (!st || !st->edit) return;
    std::ostringstream oss;
    if (st->app) {
        oss << "pcileech.exe: " << (st->app->last_exe_path.empty() ? "(unknown)" : st->app->last_exe_path) << "\r\n";
        oss << "pcileech.exe found: " << (st->app->last_exe_found ? "yes" : "no") << "\r\n";
        oss << "DMA connected: " << (st->app->last_dma_connected ? "yes" : "no") << "\r\n";
        oss << "DMA verified: " << (st->app->last_dma_verified ? "yes" : "no") << "\r\n";
        oss << "Potential DMA devices: " << st->app->last_potential_dma_count << "\r\n";
        oss << "\r\nLast status:\r\n";
        if (!st->app->last_status_detail.empty()) {
            oss << st->app->last_status_detail;
        } else {
            oss << "(none)\r\n";
        }
        oss << "\r\nLast command:\r\n";
        if (!st->app->last_command_detail.empty()) {
            oss << st->app->last_command_detail;
        } else {
            oss << "(none)\r\n";
        }
    }
    set_text(st->edit, oss.str());
}

static void debug_copy_to_clipboard(HWND hwnd, const std::wstring& text) {
    if (!OpenClipboard(hwnd)) return;
    EmptyClipboard();
    const size_t bytes = (text.size() + 1) * sizeof(wchar_t);
    HGLOBAL mem = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (mem) {
        void* p = GlobalLock(mem);
        if (p) {
            memcpy(p, text.c_str(), bytes);
            GlobalUnlock(mem);
            SetClipboardData(CF_UNICODETEXT, mem);
            mem = nullptr;
        }
    }
    if (mem) GlobalFree(mem);
    CloseClipboard();
}

static LRESULT CALLBACK DebugWndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
    DebugState* st = get_debug_state(hwnd);
    switch (msg) {
        case WM_NCCREATE: {
            auto* cs = reinterpret_cast<CREATESTRUCTW*>(lparam);
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(cs->lpCreateParams));
            return DefWindowProcW(hwnd, msg, wparam, lparam);
        }
        case WM_CREATE: {
            st = get_debug_state(hwnd);
            if (!st) return -1;
            st->hwnd = hwnd;
            st->brush_bg = CreateSolidBrush(st->color_bg);
            st->brush_edit = CreateSolidBrush(st->color_edit);
            enable_dark_title_bar(hwnd);

            const HFONT font = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));

            st->btn_refresh = CreateWindowW(L"BUTTON", L"Refresh", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                            12, 12, 100, 26, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(1)), nullptr, nullptr);
            st->btn_copy = CreateWindowW(L"BUTTON", L"Copy", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                         120, 12, 100, 26, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(2)), nullptr, nullptr);

            st->edit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                       WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL,
                                       12, 48, 860, 500, hwnd, nullptr, nullptr, nullptr);

            for (HWND ctl : {st->btn_refresh, st->btn_copy, st->edit}) {
                SendMessageW(ctl, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
            }

            debug_set_text(st);
            SetTimer(hwnd, 1, 1000, nullptr);
            return 0;
        }
        case WM_TIMER: {
            if (wparam == 1 && st) {
                debug_set_text(st);
                return 0;
            }
            return 0;
        }
        case WM_ERASEBKGND: {
            if (!st || !st->brush_bg) return DefWindowProcW(hwnd, msg, wparam, lparam);
            RECT rc;
            GetClientRect(hwnd, &rc);
            FillRect(reinterpret_cast<HDC>(wparam), &rc, st->brush_bg);
            return 1;
        }
        case WM_CTLCOLORSTATIC:
        case WM_CTLCOLOREDIT:
        case WM_CTLCOLORBTN: {
            if (!st) return DefWindowProcW(hwnd, msg, wparam, lparam);
            const HDC hdc = reinterpret_cast<HDC>(wparam);
            const HWND ctl = reinterpret_cast<HWND>(lparam);
            SetTextColor(hdc, st->color_text);
            SetBkMode(hdc, OPAQUE);
            if (ctl == st->edit) {
                SetBkColor(hdc, st->color_edit);
                return reinterpret_cast<LRESULT>(st->brush_edit ? st->brush_edit : GetStockObject(BLACK_BRUSH));
            }
            SetBkColor(hdc, st->color_bg);
            return reinterpret_cast<LRESULT>(st->brush_bg ? st->brush_bg : GetStockObject(BLACK_BRUSH));
        }
        case WM_SIZE: {
            if (!st) return 0;
            RECT rc;
            GetClientRect(hwnd, &rc);
            const int width = rc.right - rc.left;
            const int height = rc.bottom - rc.top;
            MoveWindow(st->edit, 12, 48, width - 24, height - 60, TRUE);
            return 0;
        }
        case WM_COMMAND: {
            const int id = LOWORD(wparam);
            if (!st) return 0;
            if (id == 1) {
                debug_set_text(st);
                return 0;
            }
            if (id == 2) {
                const int len = GetWindowTextLengthW(st->edit);
                std::wstring buf(static_cast<size_t>(len) + 1, L'\0');
                GetWindowTextW(st->edit, buf.data(), len + 1);
                if (!buf.empty() && buf.back() == L'\0') buf.pop_back();
                debug_copy_to_clipboard(hwnd, buf);
                return 0;
            }
            return 0;
        }
        case WM_DESTROY: {
            KillTimer(hwnd, 1);
            if (st) {
                if (st->brush_bg) {
                    DeleteObject(st->brush_bg);
                    st->brush_bg = nullptr;
                }
                if (st->brush_edit) {
                    DeleteObject(st->brush_edit);
                    st->brush_edit = nullptr;
                }
            }
            g_debug_hwnd = nullptr;
            return 0;
        }
        case WM_NCDESTROY: {
            auto* p = get_debug_state(hwnd);
            if (p) {
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
                delete p;
            }
            return 0;
        }
        default:
            return DefWindowProcW(hwnd, msg, wparam, lparam);
    }
}

static void show_debug_window(AppState* app) {
    if (g_debug_hwnd && IsWindow(g_debug_hwnd)) {
        ShowWindow(g_debug_hwnd, SW_SHOW);
        SetForegroundWindow(g_debug_hwnd);
        return;
    }

    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = DebugWndProc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = nullptr;
    wc.lpszClassName = kDebugWindowClassName;
    RegisterClassExW(&wc);

    auto* st = new DebugState();
    st->app = app;

    HWND hwnd = CreateWindowExW(0, kDebugWindowClassName, kDebugWindowTitle,
                                WS_OVERLAPPEDWINDOW,
                                CW_USEDEFAULT, CW_USEDEFAULT,
                                920, 620,
                                app ? app->hwnd : nullptr, nullptr, wc.hInstance, st);
    if (!hwnd) {
        delete st;
        return;
    }
    g_debug_hwnd = hwnd;
    if (!AnimateWindow(hwnd, 150, AW_BLEND | AW_ACTIVATE)) {
        ShowWindow(hwnd, SW_SHOW);
    }
    UpdateWindow(hwnd);
}

static std::vector<std::string> split_command_args(const std::string& s) {
    std::vector<std::string> out;
    std::string cur;
    bool in_quotes = false;
    char quote_char = 0;

    auto flush = [&]() {
        if (!cur.empty()) {
            out.push_back(cur);
            cur.clear();
        }
    };

    for (size_t i = 0; i < s.size(); ++i) {
        const char c = s[i];
        if (in_quotes) {
            if (c == quote_char) {
                in_quotes = false;
                quote_char = 0;
            } else {
                cur.push_back(c);
            }
            continue;
        }

        if (c == '"' || c == '\'') {
            in_quotes = true;
            quote_char = c;
            continue;
        }

        if (std::isspace(static_cast<unsigned char>(c))) {
            flush();
            continue;
        }

        cur.push_back(c);
    }

    flush();
    return out;
}

static void begin_status_check(AppState* st, bool verify_dma) {
    if (!try_begin_op(st, 1)) return;

    EnableWindow(st->btn_refresh, FALSE);
    SendMessageW(st->progress_dma, PBM_SETMARQUEE, TRUE, 30);
    set_text(st->label_dma, "DMA: checking...");

    std::thread([st, verify_dma]() {
        auto msg = std::make_unique<StatusResultMsg>();

        try {
            msg->exe_path = st->config->get_absolute_executable_path();
            std::string current_exe_path;
            try {
                current_exe_path = utils::get_current_executable_path();
            } catch (...) {
            }

            bool exe_is_self = false;
            if (!msg->exe_path.empty() && !current_exe_path.empty()) {
                std::error_code ec;
                exe_is_self = std::filesystem::equivalent(std::filesystem::path(msg->exe_path),
                                                          std::filesystem::path(current_exe_path),
                                                          ec) &&
                              !ec;
            }

            if (msg->exe_path.empty() || exe_is_self) {
                msg->exe_found = false;
                const std::string resolved = msg->exe_path.empty() ? "(empty)" : msg->exe_path;
                msg->detail =
                    "PCILeech executable path is not usable.\r\nResolved path: " + resolved +
                    "\r\nSet config.json pcileech.executable_path to the real pcileech.exe (example: bin\\\\pcileech.exe)\r\n";
            } else {
                msg->exe_found = utils::path_exists(msg->exe_path);
            }

            if (!msg->exe_found) {
                if (msg->detail.empty()) {
                    msg->detail =
                        "PCILeech executable not found.\r\nResolved path: " + msg->exe_path +
                        "\r\nCopy pcileech.exe next to this app, put it in bin\\\\, or update config.json pcileech.executable_path.\r\n";
                }
            } else {
                msg->potential_dma_count = potential_dma_device_count();
                if (verify_dma) {
                    msg->dma_verified = true;
                    const std::filesystem::path exe_dir = std::filesystem::path(msg->exe_path).parent_path();
                    std::vector<string> args = {msg->exe_path, "info"};
                    auto result = utils::execute_command(args, st->config->get_pcileech_config().timeout_seconds, exe_dir.string());
                    msg->dma_connected = (result.return_code == 0);

                    if (msg->dma_connected) {
                        msg->detail = "DMA device detected.\r\n";
                    } else {
                        msg->detail = "DMA not detected.\r\n";
                    }
                    msg->detail += "Potential DMA devices (heuristic): " + std::to_string(msg->potential_dma_count) + "\r\n";

                    if (!result.command_output.empty()) {
                        msg->detail += "\r\n[stdout]\r\n" + result.command_output + "\r\n";
                    }
                    if (!result.error_output.empty()) {
                        msg->detail += "\r\n[stderr]\r\n" + result.error_output + "\r\n";
                    }
                } else {
                    msg->dma_verified = false;
                    msg->dma_connected = (msg->potential_dma_count > 0);
                    if (msg->dma_connected) {
                        msg->detail = "Potential DMA device(s) detected.\r\n";
                    } else {
                        msg->detail = "No potential DMA device detected.\r\n";
                    }
                    msg->detail += "Potential DMA devices (heuristic): " + std::to_string(msg->potential_dma_count) + "\r\n";
                }
            }
        } catch (const std::exception& e) {
            msg->detail = std::string("Status check failed: ") + e.what() + "\r\n";
        }

        auto raw = msg.release();
        if (!PostMessageW(st->hwnd, WM_APP_STATUS_RESULT, 0, reinterpret_cast<LPARAM>(raw))) {
            delete raw;
            end_op(st);
        }
    }).detach();
}

static void begin_run_command(AppState* st, const std::string& cmdline) {
    if (!st) return;
    if (!try_begin_op(st, 2)) {
        st->queued_command = cmdline;
        st->has_queued_command = true;
        append_log(st->edit_log, "Busy. Queued: " + cmdline + "\r\n");
        return;
    }

    auto parts = split_command_args(cmdline);
    if (parts.empty()) {
        end_op(st);
        append_log(st->edit_log, "Enter a PCILeech command (example: info)\r\n");
        return;
    }

    EnableWindow(st->btn_run, FALSE);
    EnableWindow(st->btn_refresh, FALSE);
    SetWindowTextW(st->btn_run, L"Running...");
    append_log(st->edit_log, "> " + cmdline + "\r\n");

    std::thread([st, parts = std::move(parts), cmdline = std::move(cmdline)]() mutable {
        auto msg = std::make_unique<CommandResultMsg>();

        try {
            const std::string exe_path = st->config->get_absolute_executable_path();
            const std::filesystem::path exe_dir = std::filesystem::path(exe_path).parent_path();

            std::vector<string> args;
            args.reserve(parts.size() + 1);
            args.push_back(exe_path);
            args.insert(args.end(), parts.begin(), parts.end());

            auto result = utils::execute_command(args, st->config->get_pcileech_config().timeout_seconds, exe_dir.string());

            std::ostringstream oss;
            oss << "Exit: " << result.return_code << " (" << result.duration.count() << "ms)\r\n";
            if (!result.command_output.empty()) {
                oss << "\r\n[stdout]\r\n" << result.command_output << "\r\n";
            }
            if (!result.error_output.empty()) {
                oss << "\r\n[stderr]\r\n" << result.error_output << "\r\n";
            }
            oss << "\r\n";
            msg->text = oss.str();
        } catch (const std::exception& e) {
            msg->text = std::string("Command failed: ") + e.what() + "\r\n\r\n";
        }

        auto raw = msg.release();
        if (!PostMessageW(st->hwnd, WM_APP_COMMAND_RESULT, 0, reinterpret_cast<LPARAM>(raw))) {
            delete raw;
            end_op(st);
        }
    }).detach();
}

static void request_run_command(AppState* st) {
    if (!st) return;
    begin_run_command(st, get_edit_text(st->edit_command));
}

static AppState* get_state(HWND hwnd) {
    return reinterpret_cast<AppState*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
    AppState* st = get_state(hwnd);

    switch (msg) {
        case WM_NCCREATE: {
            auto* cs = reinterpret_cast<CREATESTRUCTW*>(lparam);
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(cs->lpCreateParams));
            return DefWindowProcW(hwnd, msg, wparam, lparam);
        }
        case WM_CREATE: {
            st = get_state(hwnd);
            st->hwnd = hwnd;
            st->brush_bg = CreateSolidBrush(st->color_bg);
            st->brush_edit = CreateSolidBrush(st->color_edit);
            enable_dark_title_bar(hwnd);

            const HFONT font = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));

            st->label_exe = CreateWindowW(L"STATIC", L"PCILeech: (resolving...)", WS_CHILD | WS_VISIBLE,
                                          12, 12, 660, 20, hwnd, nullptr, nullptr, nullptr);
            st->label_dma = CreateWindowW(L"STATIC", L"DMA: (checking...)", WS_CHILD | WS_VISIBLE,
                                          12, 34, 660, 20, hwnd, nullptr, nullptr, nullptr);

            st->progress_dma = CreateWindowW(PROGRESS_CLASSW, nullptr,
                                             WS_CHILD | WS_VISIBLE | PBS_MARQUEE,
                                             12, 58, 660, 18, hwnd, nullptr, nullptr, nullptr);

            st->btn_refresh = CreateWindowW(L"BUTTON", L"Refresh", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                            12, 84, 100, 26, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_REFRESH)), nullptr, nullptr);
            st->btn_devices = CreateWindowW(L"BUTTON", L"Devices", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                            120, 84, 100, 26, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_DEVICES)), nullptr, nullptr);
            st->btn_debug = CreateWindowW(L"BUTTON", L"Debug", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                          228, 84, 100, 26, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_DEBUG)), nullptr, nullptr);
            st->chk_auto = CreateWindowW(L"BUTTON", L"Auto", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                                         336, 84, 70, 26, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_AUTO)), nullptr, nullptr);
            SendMessageW(st->chk_auto, BM_SETCHECK, BST_CHECKED, 0);

            CreateWindowW(L"STATIC", L"Command:", WS_CHILD | WS_VISIBLE,
                          12, 120, 80, 20, hwnd, nullptr, nullptr, nullptr);

            st->edit_command = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"info",
                                               WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                                               80, 116, 500, 24, hwnd, nullptr, nullptr, nullptr);
            st->btn_run = CreateWindowW(L"BUTTON", L"Run", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                        590, 114, 82, 26, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_RUN)), nullptr, nullptr);

            st->edit_log = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                           WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL,
                                           12, 150, 660, 300, hwnd, nullptr, nullptr, nullptr);

            for (HWND ctl : {st->label_exe, st->label_dma, st->progress_dma, st->btn_refresh, st->btn_devices, st->btn_debug, st->chk_auto, st->edit_command, st->btn_run, st->edit_log}) {
                SendMessageW(ctl, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
            }

            SetTimer(hwnd, TIMER_ID_STATUS, 3000, nullptr);
            begin_status_check(st, false);
            return 0;
        }
        case WM_ERASEBKGND: {
            if (!st || !st->brush_bg) return DefWindowProcW(hwnd, msg, wparam, lparam);
            RECT rc;
            GetClientRect(hwnd, &rc);
            FillRect(reinterpret_cast<HDC>(wparam), &rc, st->brush_bg);
            return 1;
        }
        case WM_CTLCOLORSTATIC:
        case WM_CTLCOLOREDIT:
        case WM_CTLCOLORBTN: {
            if (!st) return DefWindowProcW(hwnd, msg, wparam, lparam);
            const HDC hdc = reinterpret_cast<HDC>(wparam);
            const HWND ctl = reinterpret_cast<HWND>(lparam);
            SetTextColor(hdc, st->color_text);
            SetBkMode(hdc, OPAQUE);
            if (ctl == st->edit_command || ctl == st->edit_log) {
                SetBkColor(hdc, st->color_edit);
                return reinterpret_cast<LRESULT>(st->brush_edit ? st->brush_edit : GetStockObject(BLACK_BRUSH));
            }
            SetBkColor(hdc, st->color_bg);
            return reinterpret_cast<LRESULT>(st->brush_bg ? st->brush_bg : GetStockObject(BLACK_BRUSH));
        }
        case WM_TIMER: {
            if (wparam == TIMER_ID_STATUS) {
                if (!st) return 0;
                const int busy = st->busy.load();
                if (busy != 0) {
                    const ULONGLONG since = st->busy_since.load();
                    const ULONGLONG now = GetTickCount64();
                    int timeout_seconds = 30;
                    if (st->config) {
                        timeout_seconds = st->config->get_pcileech_config().timeout_seconds;
                    }
                    const ULONGLONG max_ms = static_cast<ULONGLONG>(timeout_seconds + 10) * 1000ULL;
                    if (since != 0 && now > since && (now - since) > max_ms) {
                        end_op(st);
                        EnableWindow(st->btn_refresh, TRUE);
                        EnableWindow(st->btn_run, TRUE);
                        SetWindowTextW(st->btn_run, L"Run");
                        SendMessageW(st->progress_dma, PBM_SETMARQUEE, FALSE, 0);
                        SendMessageW(st->progress_dma, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
                        SendMessageW(st->progress_dma, PBM_SETPOS, 0, 0);
                        set_text(st->label_dma, "DMA: retrying...");
                        begin_status_check(st, false);
                    }
                    return 0;
                }
                if (!st->auto_refresh) {
                    return 0;
                }
                begin_status_check(st, false);
            }
            return 0;
        }
        case WM_COMMAND: {
            const int id = LOWORD(wparam);
            if (!st) return 0;

            if (id == ID_REFRESH) {
                begin_status_check(st, true);
                return 0;
            }
            if (id == ID_RUN) {
                request_run_command(st);
                return 0;
            }
            if (id == ID_DEVICES) {
                show_devices_window(hwnd);
                return 0;
            }
            if (id == ID_DEBUG) {
                show_debug_window(st);
                return 0;
            }
            if (id == ID_AUTO) {
                st->auto_refresh = (SendMessageW(st->chk_auto, BM_GETCHECK, 0, 0) == BST_CHECKED);
                if (st->auto_refresh && st->busy.load() == 0) {
                    begin_status_check(st, false);
                }
                return 0;
            }
            return 0;
        }
        case WM_APP_STATUS_RESULT: {
            auto msg_ptr = std::unique_ptr<StatusResultMsg>(reinterpret_cast<StatusResultMsg*>(lparam));
            if (st && msg_ptr) {
                const bool status_changed =
                    (st->last_exe_found != msg_ptr->exe_found) ||
                    (st->last_dma_connected != msg_ptr->dma_connected) ||
                    (st->last_dma_verified != msg_ptr->dma_verified) ||
                    (st->last_potential_dma_count != msg_ptr->potential_dma_count) ||
                    (st->last_exe_path != msg_ptr->exe_path) ||
                    (st->last_status_detail != msg_ptr->detail);

                if (msg_ptr->exe_path.empty()) {
                    set_text(st->label_exe, "PCILeech: (not configured)");
                } else {
                    set_text(st->label_exe, "PCILeech: " + msg_ptr->exe_path + (msg_ptr->exe_found ? " (found)" : " (missing)"));
                }
                if (msg_ptr->dma_verified) {
                    set_text(st->label_dma, std::string("DMA: ") + (msg_ptr->dma_connected ? "CONNECTED" : "NOT CONNECTED"));
                } else {
                    if (msg_ptr->potential_dma_count > 0) {
                        set_text(st->label_dma, "DMA: POSSIBLE (" + std::to_string(msg_ptr->potential_dma_count) + ")");
                    } else {
                        set_text(st->label_dma, "DMA: NONE");
                    }
                }

                SendMessageW(st->progress_dma, PBM_SETMARQUEE, FALSE, 0);
                SendMessageW(st->progress_dma, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
                int pos = 0;
                if (msg_ptr->dma_verified) {
                    pos = msg_ptr->dma_connected ? 100 : 0;
                } else {
                    pos = msg_ptr->potential_dma_count > 0 ? 50 : 0;
                }
                SendMessageW(st->progress_dma, PBM_SETPOS, pos, 0);

                if (status_changed && !msg_ptr->detail.empty()) {
                    append_log(st->edit_log, msg_ptr->detail);
                }

                st->last_exe_found = msg_ptr->exe_found;
                st->last_dma_connected = msg_ptr->dma_connected;
                st->last_dma_verified = msg_ptr->dma_verified;
                st->last_potential_dma_count = msg_ptr->potential_dma_count;
                st->last_exe_path = msg_ptr->exe_path;
                st->last_status_detail = msg_ptr->detail;

                EnableWindow(st->btn_refresh, TRUE);
                end_op(st);
                if (st->has_queued_command) {
                    std::string cmd = st->queued_command;
                    st->queued_command.clear();
                    st->has_queued_command = false;
                    begin_run_command(st, cmd);
                }
            }
            return 0;
        }
        case WM_APP_COMMAND_RESULT: {
            auto msg_ptr = std::unique_ptr<CommandResultMsg>(reinterpret_cast<CommandResultMsg*>(lparam));
            if (st && msg_ptr) {
                append_log(st->edit_log, msg_ptr->text);
                st->last_command_detail = msg_ptr->text;
                SetWindowTextW(st->btn_run, L"Run");
                EnableWindow(st->btn_run, TRUE);
                EnableWindow(st->btn_refresh, TRUE);
                end_op(st);
                begin_status_check(st, false);
            }
            return 0;
        }
        case WM_DESTROY: {
            KillTimer(hwnd, TIMER_ID_STATUS);
            if (st) {
                if (st->brush_bg) {
                    DeleteObject(st->brush_bg);
                    st->brush_bg = nullptr;
                }
                if (st->brush_edit) {
                    DeleteObject(st->brush_edit);
                    st->brush_edit = nullptr;
                }
            }
            PostQuitMessage(0);
            return 0;
        }
        default:
            return DefWindowProcW(hwnd, msg, wparam, lparam);
    }
}

static int run_gui() {
    INITCOMMONCONTROLSEX icc = {};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_PROGRESS_CLASS | ICC_LISTVIEW_CLASSES;
    InitCommonControlsEx(&icc);

    if (HWND console = GetConsoleWindow()) {
        ShowWindow(console, SW_HIDE);
    }

    auto state = std::make_unique<AppState>();
    try {
        state->config = std::make_unique<Config>();
    } catch (const std::exception& e) {
        MessageBoxW(nullptr, utf8_to_wide(e.what()).c_str(), L"Startup error", MB_ICONERROR | MB_OK);
        return 1;
    }

    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    wc.lpszClassName = kWindowClassName;

    if (!RegisterClassExW(&wc)) {
        MessageBoxW(nullptr, L"RegisterClassExW failed", L"Startup error", MB_ICONERROR | MB_OK);
        return 1;
    }

    HWND hwnd = CreateWindowExW(0, kWindowClassName, kWindowTitle,
                                WS_OVERLAPPEDWINDOW,
                                CW_USEDEFAULT, CW_USEDEFAULT,
                                700, 520,
                                nullptr, nullptr, wc.hInstance,
                                state.get());
    if (!hwnd) {
        MessageBoxW(nullptr, L"CreateWindowExW failed", L"Startup error", MB_ICONERROR | MB_OK);
        return 1;
    }

    if (!AnimateWindow(hwnd, 150, AW_BLEND | AW_ACTIVATE)) {
        ShowWindow(hwnd, SW_SHOW);
    }
    UpdateWindow(hwnd);

    MSG msg = {};
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    return static_cast<int>(msg.wParam);
}

static int run_mcp_server() {
    try {
        auto config = std::make_unique<Config>();
        auto server = std::make_unique<MCPServer>(*config);
        server->run();
        return 0;
    } catch (const std::exception&) {
        return 1;
    }
}

}
}

int main(int argc, char** argv) {
    HANDLE hMutex = CreateMutexW(nullptr, TRUE, L"PCILeech_MCP_Server_SingleInstance");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        if (hMutex) CloseHandle(hMutex);
        MessageBoxW(nullptr, L"Another instance is already running. Please exit the other instance first.", L"PCILeech", MB_ICONWARNING | MB_OK);
        return 1;
    }

    int result = 0;
    if (argc > 1 && std::string(argv[1]) == "--mcp") {
        result = mcp_server_pcileech::run_mcp_server();
    } else {
        result = mcp_server_pcileech::run_gui();
    }

    if (hMutex) {
        ReleaseMutex(hMutex);
        CloseHandle(hMutex);
    }
    return result;
}
