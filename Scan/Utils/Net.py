# utils/net.py (Windows 일부)
import subprocess, re, platform

def get_wifi_info_windows():
    out = subprocess.check_output("netsh wlan show interfaces", shell=True, text=True)
    ssid = re.search(r"^\s*SSID\s*:\s*(.+)$", out, re.MULTILINE)
    bssid = re.search(r"^\s*BSSID\s*:\s*(.+)$", out, re.MULTILINE)
    auth = re.search(r"^\s*Authentication\s*:\s*(.+)$", out, re.MULTILINE)
    cipher = re.search(r"^\s*Cipher\s*:\s*(.+)$", out, re.MULTILINE)
    if not ssid: return None
    sec_raw = f"{auth.group(1) if auth else ''} {cipher.group(1) if cipher else ''}"
    from scanners.wifi_info import parse_security
    return {
        "ssid": ssid.group(1).strip(),
        "bssid": bssid.group(1).strip() if bssid else None,
        "channel": None,
        "security": parse_security(sec_raw)
    }
