# platform_adapter.py
import os, platform, shutil

class PlatformAdapter:
    def get_wifi_info(self): ...
    def get_gateway_ip(self): ...

# --- Linux ---
class LinuxAdapter(PlatformAdapter):
    def __init__(self):
        self.has_nmcli = shutil.which("nmcli") is not None
    def get_wifi_info(self):
        if self.has_nmcli:
            from scanners.wifi_info import get_wifi_info_linux
            return get_wifi_info_linux()
        # Fallback: iw/wpa_cli 등 추가 가능
        return {}
    def get_gateway_ip(self):
        from scanners.gateway import get_default_gateway_linux
        return get_default_gateway_linux()

# --- Windows ---
class WindowsAdapter(PlatformAdapter):
    def get_wifi_info(self):
        from utils.net import get_wifi_info_windows
        return get_wifi_info_windows()
    def get_gateway_ip(self):
        from scanners.gateway import get_default_gateway_windows
        return get_default_gateway_windows()

def select_adapter():
    # 테스트/강제용 오버라이드 (예: WIFI_GUARD_OS=windows)
    forced = os.getenv("WIFI_GUARD_OS")
    sys = (forced or platform.system()).lower()
    if "windows" in sys:
        return WindowsAdapter()
    if "darwin" in sys or "mac" in sys:
        return MacAdapter()
    # Linux 또는 WSL 포함
    return LinuxAdapter()
