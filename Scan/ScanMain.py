# main.py
import json, platform, datetime
from scanners.wifi_info import get_wifi_info_linux, parse_security
from scanners.gateway import get_default_gateway_linux, get_default_gateway_windows, guess_brand
from scanners.portscan import scan_gateway
from scanners.tls_check import tls_probe, captive_portal_check
from utils.net import get_wifi_info_windows
from platfomr_adapter import select_adapter

def get_wifi_info():
    if platform.system() == "Windows":
        return get_wifi_info_windows()
    return get_wifi_info_linux()

def get_gateway_ip():
    return get_default_gateway_windows() if platform.system()=="Windows" else get_default_gateway_linux()

def run_scan(tls_host="example.com", mode="basic"):
    adapter = select_adapter()
    wifi = adapter.get_wifi_info() or {}
    gw = adapter.get_gateway_ip()
    ports = scan_gateway(gw) if gw and mode=="basic" else []
    tls = {}
    try:
        tp = tls_probe(tls_host)
        tls = {
            "target_host": tls_host,
            "tls_version": tp["tls_version"],
            "cert_valid": bool(tp["peer_cert"]),
            "issuer_cn": next((x[0][1] for x in tp["peer_cert"].get("issuer",[]) if x[0][0]=="commonName"), None),
            "notes": []
        }
    except Exception as e:
        tls = {"target_host": tls_host, "tls_version": None, "cert_valid": False, "issuer_cn": None, "notes": [str(e)]}

    out = {
        "meta": {"timestamp": datetime.datetime.now().astimezone().isoformat(),
                 "platform": platform.system().lower(), "mode": mode},
        "wifi": wifi,
        "network": {"gateway_ip": gw, "brand_hint": None, "captive_portal": captive_portal_check()},
        "ports": ports,
        "tls": tls
    }
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return out
if __name__ == "__main__":
    run_scan()
