# scanners/wifi_info.py
import subprocess, re

def run(cmd):
    """
    쉘 명령을 실행하고 문자열로 반환한다.
    - text=True  : Python3에서 bytes 대신 str 반환
    - stderr=STDOUT : 표준에러를 표준출력으로 합쳐 디버깅을 쉽게 함
    예외:
      - 명령 실패 시 subprocess.CalledProcessError 발생 가능
    """
    return subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.STDOUT)

def parse_security(sec_str: str):
    """
    nmcli SECURITY 필드(예: 'WPA2 WPA3', 'RSN', 'WEP', '', 'NONE', 'SAE')를 해석해
    보안모드와 주요 플래그를 판별한다.

    매핑/판정 규칙:
      - OPEN      : 비어있거나 'NONE' 포함
      - WEP       : 'WEP' 포함
      - WPA2      : 'WPA2' 또는 'RSN' 포함 (RSN은 WPA2 표준을 의미)
      - WPA3      : 'WPA3' 또는 'SAE' 포함
      - 전환모드  : WPA2와 WPA3 신호가 동시에 보이면 True로 간주(휴리스틱)

    반환:
      {
        "mode": "OPEN" | "WEP" | "WPA2" | "WPA3" | "WPA2/WPA3",
        "is_open": bool,
        "is_wep": bool,
        "is_wpa3_transition": bool
      }
    """
    s = sec_str.upper()

    # OPEN: 완전 비보호(포털은 별개) — nmcli가 빈 문자열/ "NONE"로 표기하는 경우가 있음
    is_open = (s.strip() == "" or "NONE" in s)

    # WEP: 레거시 취약 암호화
    is_wep = "WEP" in s

    # WPA2: 'WPA2' 또는 'RSN'(=WPA2) 표기를 모두 허용
    has_wpa2 = "WPA2" in s or "RSN" in s

    # WPA3: 'WPA3' 또는 'SAE'(WPA3 SAE 인증)를 허용
    has_wpa3 = "WPA3" in s or "SAE" in s

    # 전환모드(Transition): 동일 SSID에서 WPA2와 WPA3를 동시에 광고하는 환경
    # - 다운그레이드(호환) 연결 위험이 있어 감점 요인으로 쓰임
    is_transition = (has_wpa2 and has_wpa3)

    # 사용자 친화적 모드 라벨 구성
    # 우선순위: OPEN > WEP > 순수 WPA3 > 전환모드(WPA2/WPA3) > 순수 WPA2
    mode = (
        "OPEN" if is_open else
        ("WEP" if is_wep else
         ("WPA3" if (has_wpa3 and not has_wpa2) else
          ("WPA2/WPA3" if is_transition else "WPA2")))
    )

    return {
        "mode": mode,
        "is_open": is_open,
        "is_wep": is_wep,
        "is_wpa3_transition": is_transition
    }

def get_wifi_info_linux():
    """
    현재 연결된 Wi-Fi 정보를 nmcli로 조회해 주요 필드를 파싱한다.
    - ACTIVE == 'yes' 인 한 줄만을 선택(현재 연결된 네트워크)
    - 필드: ACTIVE, SSID, BSSID, CHAN, SECURITY (':'로 구분)

    반환:
      {
        "ssid": <str>,
        "bssid": <str>,
        "channel": <str>,
        "security": <dict from parse_security>
      }
    또는 연결 정보가 없을 경우 None
    """
    # -t : 간략(terse) 출력, 콜론 구분
    # -f : 필요한 필드만 선택
    out = run("nmcli -t -f ACTIVE,SSID,BSSID,CHAN,SECURITY dev wifi")

    # 여러 라인이 나올 수 있으나, 현재 연결된 항목은 ACTIVE == "yes"
    for line in out.splitlines():
        parts = line.strip().split(":")
        # parts 예: ['yes', 'Cafe_Free_WiFi', 'AA:BB:CC:DD:EE:FF', '11', 'WPA2 WPA3']
        if len(parts) >= 5 and parts[0] == "yes":
            # 순서 고정: ACTIVE, SSID, BSSID, CHAN, SECURITY
            _, ssid, bssid, chan, sec = parts[:5]

            return {
                "ssid": ssid,          # 네트워크 이름(SSID)
                "bssid": bssid,        # AP MAC 주소(BSSID)
                "channel": chan,       # 채널 번호(문자열로 반환)
                "security": parse_security(sec)  # 보안 모드 판정 결과
            }

    # 현재 연결이 없거나 파싱 실패 시
    return None
