# scanners/tls_check.py
from __future__ import annotations
import socket
import ssl
from typing import Dict, Optional


def check_tcp(host: str = "example.com", port: int = 443, timeout: float = 3.0) -> Dict[str, Optional[str]]:
    """
    지정한 host:port로 TCP 3-way 핸드셰이크를 시도해
    'open/closed/filtered/unreachable' 상태를 판별한다.

    매핑 규칙:
      - 정상 연결 성공 → {"state": "open"}
      - ConnectionRefusedError → {"state": "closed", "error": "refused"}       # 포트 닫힘
      - socket.timeout → {"state": "filtered", "error": "timeout"}              # 방화벽/필터링/지연
      - 기타 OSError → {"state": "unreachable", "error": "<시스템 메시지>"}     # 라우팅/네트워크 문제 등

    Args:
        host: 검사 대상 호스트명 또는 IP
        port: 검사 대상 포트 (기본 443)
        timeout: TCP 연결 타임아웃(초)

    Returns:
        상태 딕셔너리. 예) {"state":"open"} 또는 {"state":"closed","error":"refused"}
    """
    try:
        # TCP 소켓을 열고 지정 host:port에 연결을 시도한다.
        # with 블록을 벗어나면 소켓은 자동으로 닫힌다.
        with socket.create_connection((host, port), timeout=timeout):
            return {"state": "open"}
    except socket.timeout:
        # SYN 패킷에 대한 응답 지연/드롭 → 타임아웃. 흔히 'filtered'로 간주.
        return {"state": "filtered", "error": "timeout"}
    except ConnectionRefusedError:
        # 대상 호스트가 RST로 거부 → 포트가 명확히 닫혀 있음(closed)
        return {"state": "closed", "error": "refused"}
    except OSError as e:
        # 기타 네트워크 오류(호스트 미도달, 네임 해석 실패 등)
        # strerror가 없는 플랫폼도 있어 str(e)로 보조.
        return {"state": "unreachable", "error": getattr(e, "strerror", str(e))}


def tls_probe(host: str = "example.com", port: int = 443, timeout: float = 3.0) -> Dict[str, Optional[str]]:
    """
    TCP 도달성을 먼저 확인한 뒤, 가능할 경우 TLS 핸드셰이크를 수행하여
    TLS 버전/인증서 정보를 수집한다.

    처리 흐름:
      1) check_tcp()로 TCP 연결 가능 여부 판단
      2) open 이면 ssl.wrap_socket으로 핸드셰이크
      3) 성공 시:
         - ssock.version(): "TLSv1.3"/"TLSv1.2" 등
         - getpeercert()의 issuer DN에서 commonName(CN) 추출
      4) 실패 시:
         - ssl.SSLCertVerificationError: 인증서 검증 실패(자체서명, 이름 불일치 등)
         - ssl.SSLError: 기타 TLS 오류(프로토콜 불일치, 핸드셰이크 실패 등)
         - Exception: 알 수 없는 예외

    Args:
        host: TLS 서버 호스트네임 (SNI/hostname 검증에 사용)
        port: TLS 포트 (기본 443)
        timeout: TCP 연결 타임아웃(초)

    Returns:
        결과 딕셔너리(상단 스키마 참고).
    """
    # 1) TCP 도달성 선검사
    tcp = check_tcp(host, port, timeout)
    if tcp["state"] != "open":
        # TCP 레벨에서 막힌 경우 → TLS 검사를 시도하지 않고 이유만 반환
        return {
            "reachable": False,                     # TLS 레벨까지 가지 못했음
            "reason": tcp.get("error", tcp["state"]),  # "refused", "timeout", "unreachable" 등
            "tls_version": None,
            "cert_valid": False,
            "issuer_cn": None,
            # error_detail은 선택 필드: TCP 단계에서는 불필요하므로 생략 가능
        }

    # 2) TLS 핸드셰이크 시도
    try:
        # 기본 컨텍스트: 시스템 신뢰 저장소를 사용하여 서버 인증서 체인 검증 + 호스트네임 검증 수행
        ctx = ssl.create_default_context()

        # TCP 소켓 연결 후 TLS로 래핑
        with socket.create_connection((host, port), timeout=timeout) as sock:
            # server_hostname 인자를 전달해야 SNI/호스트네임 검증이 정상 작동한다.
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()   # 서버 인증서(사전형) — 검증 실패 시 여기까지 오지 못함
                issuer_cn = None

                # issuer는 ((("commonName", "Let's Encrypt"),), (("countryName","US"),), ...) 형태
                for rdn in cert.get("issuer", []):         # RDNs 리스트
                    if rdn and rdn[0][0] == "commonName":  # 첫 튜플의 첫 속성이 "commonName"인지 확인
                        issuer_cn = rdn[0][1]               # CN 문자열
                        break

                return {
                    "reachable": True,          # TCP/TLS 모두 성공적으로 진행
                    "reason": None,             # 실패 사유 없음
                    "tls_version": ssock.version(),  # 예: "TLSv1.3"
                    "cert_valid": True,         # 기본 정책 기준 검증 완료
                    "issuer_cn": issuer_cn,     # 발급자 CN (없을 수도 있음)
                }

    except ssl.SSLCertVerificationError as e:
        # 인증서 체인이 신뢰할 수 없거나, 호스트네임이 불일치 등 검증 실패
        # 보안 관점에서 중요한 시그널이므로 구분해서 반환
        return {
            "reachable": True,                 # TCP/TLS 채널은 열렸으나
            "reason": "cert_verify_failed",    # 검증 단계에서 실패
            "tls_version": None,               # 버전 확인 전 실패할 수 있음
            "cert_valid": False,
            "issuer_cn": None,
            "error_detail": str(e),            # UI/로그 참고용(노출 과다 주의)
        }

    except ssl.SSLError as e:
        # 프로토콜/암호군 불일치, 중간자, 레코드 손상 등 핸드셰이크 레벨의 일반적인 오류
        return {
            "reachable": True,                 # TCP는 열림
            "reason": "tls_handshake_failed",  # TLS 레벨 실패
            "tls_version": None,
            "cert_valid": False,
            "issuer_cn": None,
            "error_detail": str(e),
        }

    except Exception as e:
        # 예측하지 못한 모든 예외를 포괄적으로 수집(안정성)
        return {
            "reachable": True,                 # TCP는 열렸음
            "reason": "unknown_tls_error",     # 원인 미상
            "tls_version": None,
            "cert_valid": False,
            "issuer_cn": None,
            "error_detail": str(e),
        }
