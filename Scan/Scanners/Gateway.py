# scanners/gateway.py
import re, subprocess, requests

def get_default_gateway_linux():
    out = subprocess.check_output("ip route", shell=True, text=True)
    m = re.search(r"default via ([0-9.]+)", out)
    return m.group(1) if m else None

def get_default_gateway_windows():
    out = subprocess.check_output("route print 0.0.0.0", shell=True, text=True)
    m = re.search(r"0\.0\.0\.0\s+0\.0\.0\.0\s+([0-9.]+)", out)
    return m.group(1) if m else None

def guess_brand(gw_ip):
    try:
        r = requests.get(f"http://{gw_ip}", timeout=2)
        text = (r.text[:200] if r.text else "") + " " + " ".join([f"{k}:{v}" for k,v in r.headers.items()])
        for k in ["ipTIME","KT","SK","U+","TP-LINK","NETGEAR","D-LINK","ASUS","CISCO","HUAWEI","ZTE","Arris","MikroTik"]:
            if k.lower() in text.lower():
                return k
        # 로그인/관리자 키워드
        if re.search(r"(login|admin|관리자|로그인)", text, re.I):
            return "Unknown(AdminPage)"
    except Exception:
        pass
    return None
