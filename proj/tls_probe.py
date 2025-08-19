# tls_probe.py — Python 3.8+ / 표준 ssl 모듈 사용
import argparse, json, socket, ssl, sys
from datetime import datetime, timezone
import ipaddress

def is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s); return True
    except Exception:
        return False

_ABBR = {
    "commonName": "CN",
    "organizationName": "O",
    "organizationalUnitName": "OU",
    "countryName": "C",
    "localityName": "L",
    "stateOrProvinceName": "ST",
}

def rdn_to_str(subject):
    parts = []
    try:
        for rdn in subject or []:
            for atv in rdn:
                if isinstance(atv, tuple) and len(atv) >= 2:
                    k, v = atv[0], atv[1]
                    key = _ABBR.get(k, k)
                    parts.append(f"{key}={v}")
    except Exception:
        pass
    return ", ".join(parts)

def parse_dates(cert_dict):
    out = {"not_before":"", "not_after":"", "days_left":0}
    try:
        if cert_dict.get("notAfter"):
            ts = ssl.cert_time_to_seconds(cert_dict["notAfter"])
            dt = datetime.fromtimestamp(ts, tz=timezone.utc)
            out["not_after"] = dt.strftime("%Y-%m-%d")
            out["days_left"] = (dt - datetime.now(timezone.utc)).days
        if cert_dict.get("notBefore"):
            ts2 = ssl.cert_time_to_seconds(cert_dict["notBefore"])
            dt2 = datetime.fromtimestamp(ts2, tz=timezone.utc)
            out["not_before"] = dt2.strftime("%Y-%m-%d")
    except Exception:
        pass
    return out

def connect(host, port, sni, verify_name, timeout, verify=True):
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if verify and verify_name:
        ctx.check_hostname = True
    else:
        ctx.check_hostname = False
    if not verify:
        ctx.verify_mode = ssl.CERT_NONE
        ctx.check_hostname = False

    server_hostname = None if (not sni or is_ip(sni)) else sni
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=server_hostname) as ssock:
            ver = ssock.version() or ""
            cipher = (ssock.cipher() or ["", "", 0])[0]
            cert = ssock.getpeercert() or {}
            dates = parse_dates(cert)
            subject = rdn_to_str(cert.get("subject"))
            issuer  = rdn_to_str(cert.get("issuer"))

            hostname_ok = False
            if verify and verify_name:
                hostname_ok = True
            elif verify_name:
                try:
                    ssl.match_hostname(cert, verify_name)
                    hostname_ok = True
                except Exception:
                    hostname_ok = False

            self_signed = bool(subject) and subject == issuer
            return {
                "supported": True,
                "version": ver.replace("v","").replace("TLS","TLS"),
                "cipher": cipher,
                "certSubject": subject,
                "certIssuer": issuer,
                "notBefore": dates.get("not_before",""),
                "notAfter":  dates.get("not_after",""),
                "daysLeft":  dates.get("days_left",0),
                "validChain": bool(verify),
                "hostnameMatch": hostname_ok,
                "selfSigned": self_signed
            }

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--sni", default="")
    ap.add_argument("--verify-name", dest="vname", default="")
    ap.add_argument("--timeout", type=float, default=3.0)
    args = ap.parse_args()

    try:
        out = connect(args.host, args.port, args.sni or args.vname, args.vname, args.timeout, verify=True)
        print(json.dumps(out, ensure_ascii=False))
        return 0
    except ssl.SSLCertVerificationError:
        try:
            out = connect(args.host, args.port, args.sni or args.vname, args.vname, args.timeout, verify=False)
            out["validChain"] = False
            out["hostnameMatch"] = False
            print(json.dumps(out, ensure_ascii=False))
            return 0
        except Exception as e2:
            print(json.dumps({"supported": False, "error": str(e2)}, ensure_ascii=False))
            return 0
    except Exception as e:
        print(json.dumps({"supported": False, "error": str(e)}, ensure_ascii=False))
        return 0

if __name__ == "__main__":
    sys.exit(main())
