# scanners/portscan.py
import socket, concurrent.futures

COMMON_PORTS = [80,443,22,23,53,7547,1900,5000,8443]

def is_open(ip, port, timeout=0.6):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            s.connect((ip, port))
            return True
        except:
            return False

def grab_http_banner(ip, port=80, timeout=1.0):
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.sendall(b"GET / HTTP/1.1\r\nHost: router\r\nUser-Agent: WiFiGuard\r\nConnection: close\r\n\r\n")
            data = s.recv(4096)
            return data.decode(errors="ignore")
    except:
        return None

def scan_gateway(ip):
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
        futs = {ex.submit(is_open, ip, p): p for p in COMMON_PORTS}
        for fut in concurrent.futures.as_completed(futs):
            p = futs[fut]
            open_ = fut.result()
            rec = {"port": p, "state": "open" if open_ else "closed"}
            if open_ and p in (80,8080,8000,5000,8443,443):
                banner = grab_http_banner(ip, 80 if p==443 else p)
                rec["service_hint"] = "https" if p==443 else "http"
                if banner:
                    # 간단 요약
                    head = banner.splitlines()[0] if "\n" in banner else banner[:80]
                    rec["banner"] = head[:120]
            results.append(rec)
    return results
