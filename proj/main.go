// main.go — Windows 공용 Wi-Fi 안전도 평가 PoC (DB 규칙 연동 포함)
// - netsh 파싱, 캡티브 포털 감지, 게이트웨이 포트 스캔(확장), 로컬 LISTEN 수집
// - TLS 검사: Python ssl 프로브 호출 (리디렉션/본문 https 링크/추측 포트)
// - 위험 점수/대시보드, 포트 위험 정렬, 게이트웨이/포털 TLS 표
// - OpenAI 요약(JSON 스키마) + 로컬요약 폴백
// - DB 규칙(rs)로 'kiosk/staff/guest/unknown' 분류
// 빌드: go build -o wifiagent.exe
// 실행: wifiagent.exe → http://127.0.0.1:18080
package main

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---------- UI / Python 스크립트 임베드 ----------

//go:embed ui.html
var uiFS embed.FS

//go:embed tls_probe.py
var tlsProbePy string

// ---------- 설정 ----------

var (
	openAIHost   = getenvDefault("OPENAI_HOST", "https://api.openai.com")
	openAIModel  = getenvDefault("OPENAI_MODEL", "gpt-4o-mini")
	openAIAPIKey = os.Getenv("OPENAI_API_KEY")

	reqTimeout = 6 * time.Second
	pshellTO   = 5 * time.Second

	// 포트 확장(비표준 HTTPS 포함)
	gatewayPorts = []int{21, 22, 23, 53, 80, 443, 4443, 4433, 8080, 8443, 7001, 7547, 9443, 10443}

	// 규칙셋 핸들(초기화 실패 시 nil → 폴백)
	gRules *ruleset
)

func getenvDefault(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

// ---------- 데이터 구조 ----------

type ScanResult struct {
	Ts       string `json:"ts"`
	OS       string `json:"os"`
	Iface    string `json:"iface"`
	SSID     string `json:"ssid"`
	BSSID    string `json:"bssid"`
	PHY      string `json:"phy"`
	Band     string `json:"band"`
	Channel  int    `json:"channel"`
	Auth     string `json:"auth"`
	Cipher   string `json:"cipher"`
	PMF      string `json:"pmf"`
	SignalPc int    `json:"signalPct"`
}

type ScoreInput struct {
	Scan ScanResult `json:"scan"`
}

type ScoreBreakdown struct {
	Auth   int `json:"auth"`
	Cipher int `json:"cipher"`
	PMF    int `json:"pmf"`
	Portal int `json:"portal"`
	Ports  int `json:"ports"`
}

type ListeningPort struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
	PID     int    `json:"pid"`
}

type PortRisk struct {
	Port   int    `json:"port"`
	Risk   int    `json:"risk"`
	Reason string `json:"reason"`
}

type LocalPortRisk struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
	PID     int    `json:"pid"`
	Risk    int    `json:"risk"`
	Reason  string `json:"reason"`
}

type TLSDiag struct {
	Host          string   `json:"host"`
	Port          int      `json:"port"`
	Supported     bool     `json:"supported"`
	TLSVersion    string   `json:"tlsVersion"`
	CipherSuite   string   `json:"cipherSuite"`
	ServerName    string   `json:"serverName"`
	CertSubject   string   `json:"certSubject"`
	CertIssuer    string   `json:"certIssuer"`
	NotBefore     string   `json:"notBefore"`
	NotAfter      string   `json:"notAfter"`
	DaysLeft      int      `json:"daysLeft"`
	ValidChain    bool     `json:"validChain"`
	HostnameMatch bool     `json:"hostnameMatch"`
	SelfSigned    bool     `json:"selfSigned"`
	OCSPStapled   bool     `json:"ocspStapled"`
	Score         int      `json:"score"`
	Reasons       []string `json:"reasons"`
}

type TLSSummary struct {
	Gateway []TLSDiag `json:"gateway"`
	Portal  *TLSDiag  `json:"portal,omitempty"`
	NoteGW  string    `json:"noteGateway,omitempty"`
	NotePT  string    `json:"notePortal,omitempty"`
}

type UseGuess struct {
	Label      string   `json:"label"`      // kiosk | staff | guest | unknown
	Confidence int      `json:"confidence"` // 0~100
	Reasons    []string `json:"reasons"`
}

type ScoreResult struct {
	Score                  int             `json:"score"`
	Level                  string          `json:"level"`
	Reasons                []string        `json:"reasons"`
	Recommendations        []string        `json:"recommendations"`
	CaptivePortal          string          `json:"captivePortal"`
	PortalHost             string          `json:"portalHost,omitempty"`
	Breakdown              ScoreBreakdown  `json:"breakdown"`
	Gateway                string          `json:"gateway"`
	GatewayOpen            []int           `json:"gatewayOpenPorts"`
	GatewayOpenDetailed    []PortRisk      `json:"gatewayOpenDetailed"`
	LocalListening         []ListeningPort `json:"localListening"`
	LocalListeningDetailed []LocalPortRisk `json:"localListeningDetailed"`
	TLS                    TLSSummary      `json:"tls"`
	UseGuess               UseGuess        `json:"useGuess"`
}

type Report struct {
	Scan  ScanResult  `json:"scan"`
	Score ScoreResult `json:"score"`
}

// ---------- 정규식/파서 ----------

var reLabels = map[string][]*regexp.Regexp{
	"ssid":      {re(`(?m)^\s*SSID\s*[:：]\s*(.+)$`)},
	"bssid":     {re(`(?m)^\s*BSSID\s*[:：]\s*([0-9A-Fa-f:\-]+)$`)},
	"auth":      {re(`(?m)^\s*((?i)Authentication|인증)\s*[:：]\s*(.+)$`)},
	"cipher":    {re(`(?m)^\s*((?i)Cipher|암호화)\s*[:：]\s*(.+)$`)},
	"radio":     {re(`(?m)^\s*((?i)Radio\s+type|송수신\s*장치\s*종류)\s*[:：]\s*(.+)$`)},
	"band":      {re(`(?m)^\s*((?i)Band|밴드)\s*[:：]\s*(.+)$`)},
	"channel":   {re(`(?m)^\s*((?i)Channel|채널)\s*[:：]\s*(\d+)`)},
	"signalPct": {re(`(?m)^\s*((?i)Signal|신호)\s*[:：]\s*(\d+)\s*%`)},
}
var reHTTPSLink = regexp.MustCompile(`https://[A-Za-z0-9\-\.:_%\[\]]+`)

func re(p string) *regexp.Regexp { return regexp.MustCompile(p) }

func pick1(txt string, keys ...string) string {
	for _, k := range keys {
		if regs, ok := reLabels[k]; ok {
			for _, r := range regs {
				if m := r.FindStringSubmatch(txt); len(m) >= 2 {
					val := m[len(m)-1]
					return strings.TrimSpace(val)
				}
			}
		}
	}
	return ""
}

// ---------- 유틸 ----------

func normalizeText(s string) string {
	replacer := strings.NewReplacer("\u00A0", " ", "\uFEFF", "", "\uFF1A", ":")
	s = replacer.Replace(s)
	return strings.ReplaceAll(s, "\r\n", "\n")
}
func sanitizeMAC(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.ReplaceAll(s, "-", ":")
}
func upperNoSpace(s string) string { return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(s), " ", "")) }
func containsAny(s string, needles ...string) bool {
	S := strings.ToUpper(s)
	for _, n := range needles {
		if strings.Contains(S, strings.ToUpper(n)) {
			return true
		}
	}
	return false
}
func atoi(s string) int { i, _ := strconv.Atoi(strings.TrimSpace(s)); return i }
func clamp01(x int) int {
	if x < 0 {
		return 0
	}
	if x > 100 {
		return 100
	}
	return x
}
func uniqueNonEmpty(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}
func escapeJSON(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s)
}
func isIP(host string) bool { return net.ParseIP(host) != nil }
func maskBSSID(b string) string {
	parts := strings.Split(strings.ToLower(b), ":")
	if len(parts) < 6 {
		return b
	}
	return strings.Join(parts[:4], ":") + ":**:**"
}
func emptyDash(s string) string { if strings.TrimSpace(s) == "" { return "-" }; return s }

// ---------- 표준화 ----------

func normAuth(raw string) string {
	s := upperNoSpace(raw)
	switch {
	case s == "" || s == "OPEN" || containsAny(s, "개방", "공개", "OPENAUTH"):
		return "OPEN"
	case containsAny(s, "OWE", "ENHANCEDOPEN", "강화된개방"):
		return "OWE"
	case containsAny(s, "WPA3", "SAE") && containsAny(s, "ENTERPRISE", "EAP", "기업", "엔터프라이즈"):
		return "WPA3-EAP"
	case containsAny(s, "WPA3", "SAE"):
		return "WPA3-SAE"
	case containsAny(s, "WPA2") && containsAny(s, "ENTERPRISE", "EAP", "기업", "엔터프라이즈"):
		return "WPA2-EAP"
	case containsAny(s, "WPA2", "PSK", "PERSONAL", "개인", "퍼스널"):
		return "WPA2-PSK"
	case containsAny(s, "WEP"):
		return "WEP"
	default:
		if containsAny(s, "WPA") && containsAny(s, "PERSONAL", "개인", "PSK") {
			return "WPA2-PSK"
		}
		return "UNKNOWN"
	}
}
func normCipher(raw string) string {
	s := strings.ToUpper(strings.TrimSpace(raw))
	switch {
	case strings.Contains(s, "GCMP"):
		return "GCMP"
	case strings.Contains(s, "CCMP"):
		return "CCMP"
	case strings.Contains(s, "TKIP"):
		return "TKIP"
	case strings.Contains(s, "WEP"):
		return "WEP"
	case s == "" || containsAny(s, "NONE", "없음"):
		return "NONE"
	default:
		return "UNKNOWN"
	}
}
func normBand(raw string, channel int) string {
	r := strings.ReplaceAll(strings.ToLower(raw), " ", "")
	switch {
	case strings.Contains(r, "2.4"):
		return "2.4"
	case strings.Contains(r, "5ghz") || strings.Contains(r, "5.0") || r == "5ghz" || r == "5":
		return "5"
	case strings.Contains(r, "6ghz") || strings.Contains(r, "6.0") || r == "6ghz" || r == "6":
		return "6"
	}
	switch {
	case channel >= 1 && channel <= 14:
		return "2.4"
	case channel >= 36 && channel <= 177:
		return "5"
	case channel >= 1 && channel <= 233:
		return "6"
	default:
		return ""
	}
}

// ---------- Windows 스캔 ----------

func scanWindows() (*ScanResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), pshellTO)
	defer cancel()
	out, err := exec.CommandContext(ctx, "cmd", "/C", "chcp 65001 >NUL & netsh wlan show interfaces").CombinedOutput()
	if err != nil {
		return nil, err
	}
	txt := normalizeText(string(out))
	if !strings.Contains(txt, "SSID") && !strings.Contains(txt, "BSSID") && !strings.Contains(txt, "Authentication") && !strings.Contains(txt, "인증") {
		return nil, errors.New("unexpected netsh output")
	}
	ssid := pick1(txt, "ssid")
	bssid := sanitizeMAC(pick1(txt, "bssid"))
	authRaw := pick1(txt, "auth")
	ciphRaw := pick1(txt, "cipher")
	radio := pick1(txt, "radio")
	bandRaw := pick1(txt, "band")
	ch := atoi(pick1(txt, "channel"))
	signal := atoi(pick1(txt, "signalPct"))

	return &ScanResult{
		Ts:       time.Now().Format(time.RFC3339),
		OS:       runtime.GOOS,
		Iface:    "Wi-Fi",
		SSID:     strings.TrimSpace(ssid),
		BSSID:    bssid,
		PHY:      strings.TrimSpace(radio),
		Band:     normBand(bandRaw, ch),
		Channel:  ch,
		Auth:     normAuth(authRaw),
		Cipher:   normCipher(ciphRaw),
		PMF:      "unknown",
		SignalPc: signal,
	}, nil
}

// ---------- 포털 감지 ----------

type PortalCheck struct {
	Status string // none|suspected|blocked
	Host   string // 리디렉션 FQDN
	From   string // 사용된 엔드포인트명
}

func captivePortalCheckMulti() PortalCheck {
	endpoints := []struct {
		Name string
		URL  string
	}{
		{"gstatic", "http://connectivitycheck.gstatic.com/generate_204"},
		{"msft", "http://www.msftconnecttest.com/connecttest.txt"},
		{"apple", "http://captive.apple.com/hotspot-detect.html"},
	}
	client := &http.Client{
		Timeout: reqTimeout,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{Timeout: 1500 * time.Millisecond}).DialContext,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}

	for _, ep := range endpoints {
		req, _ := http.NewRequest("GET", ep.URL, nil)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		func() { defer resp.Body.Close() }()
		if resp.StatusCode == 204 {
			return PortalCheck{Status: "none", From: ep.Name}
		}
		loc := resp.Header.Get("Location")
		var host string
		if loc != "" {
			if u, err2 := url.Parse(loc); err2 == nil {
				host = u.Hostname()
			}
		}
		if resp.StatusCode/100 == 3 {
			return PortalCheck{Status: "suspected", Host: host, From: ep.Name}
		}
		if resp.StatusCode == 200 {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			if len(b) > 0 {
				return PortalCheck{Status: "suspected", Host: host, From: ep.Name}
			}
		}
	}
	return PortalCheck{Status: "blocked"}
}

// ---------- PowerShell/네트워크 ----------

func psUTF8(cmd string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), pshellTO)
	defer cancel()
	full := "[Console]::OutputEncoding=[Text.Encoding]::UTF8; " + cmd
	return exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", full).CombinedOutput()
}

func getDefaultGateway() string {
	out, err := psUTF8(`(Get-NetIPConfiguration | Where-Object {$_.IPv4DefaultGateway -ne $null} | Select-Object -First 1).IPv4DefaultGateway.NextHop`)
	if err != nil {
		return ""
	}
	gw := strings.TrimSpace(string(out))
	gw = strings.Trim(gw, "\" \r\n\t")
	if net.ParseIP(gw) == nil {
		return ""
	}
	return gw
}

func probeGatewayPorts(gateway string, ports []int) []int {
	var open []int
	dialer := net.Dialer{Timeout: 900 * time.Millisecond} // 상향
	for _, p := range ports {
		addr := net.JoinHostPort(gateway, strconv.Itoa(p))
		conn, err := dialer.Dial("tcp", addr)
		if err == nil {
			open = append(open, p)
			_ = conn.Close()
		}
	}
	return open
}

type psPort struct {
	LocalAddress  string `json:"LocalAddress"`
	LocalPort     int    `json:"LocalPort"`
	OwningProcess int    `json:"OwningProcess"`
}

func listLocalListening() []ListeningPort {
	out, err := psUTF8(`Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess | ConvertTo-Json -Compress`)
	if err != nil || len(out) == 0 {
		return nil
	}
	var arr []psPort
	if strings.HasPrefix(strings.TrimSpace(string(out)), "{") {
		var one psPort
		if json.Unmarshal(out, &one) == nil {
			arr = []psPort{one}
		}
	} else {
		_ = json.Unmarshal(out, &arr)
	}
	var res []ListeningPort
	for _, x := range arr {
		res = append(res, ListeningPort{Address: x.LocalAddress, Port: x.LocalPort, PID: x.OwningProcess})
	}
	return res
}

// ---------- 대시보드 퍼센트 ----------

func pctAuth(a string) int {
	switch a {
	case "WPA3-EAP":
		return 100
	case "WPA3-SAE":
		return 85
	case "WPA2-EAP":
		return 75
	case "WPA2-PSK":
		return 65
	case "OWE":
		return 40
	case "OPEN", "WEP":
		return 0
	default:
		return 50
	}
}
func pctCipher(c string) int {
	switch c {
	case "GCMP":
		return 100
	case "CCMP":
		return 90
	case "TKIP":
		return 10
	case "WEP", "NONE":
		return 0
	default:
		return 50
	}
}
func pctPMF(p string) int {
	switch p {
	case "required":
		return 100
	case "optional":
		return 50
	case "disabled":
		return 0
	default:
		return 50
	}
}
func pctPortal(cp string) int {
	switch cp {
	case "none":
		return 100
	case "suspected":
		return 40
	case "blocked":
		return 30
	default:
		return 50
	}
}

// ---------- 포트 위험도 ----------

func gatewayPortRisk(p int) (risk int, reason string) {
	switch p {
	case 23:
		return 100, "Telnet(평문 원격관리)"
	case 21:
		return 90, "FTP(평문 인증)"
	case 7547:
		return 80, "TR-069/CWMP(원격관리)"
	case 80:
		return 60, "HTTP(평문 관리/웹 UI)"
	case 8080:
		return 55, "HTTP Alt(관리 가능)"
	case 22:
		return 50, "SSH(강한 자격 필요)"
	case 53:
		return 45, "DNS 응답 노출"
	case 8443:
		return 40, "HTTPS Alt(관리 가능)"
	case 443:
		return 30, "HTTPS(암호화된 UI)"
	case 9443, 10443, 4443, 4433, 7001:
		return 35, "HTTPS Alt(벤더 관행)"
	default:
		if p < 1024 {
			return 50, "Well-known 포트"
		}
		return 35, "임의 포트"
	}
}
func localPortRisk(port int) (risk int, reason string) {
	switch port {
	case 3389:
		return 100, "RDP(원격 데스크톱)"
	case 445:
		return 90, "SMB 파일공유"
	case 139:
		return 80, "NetBIOS-SSN"
	case 135:
		return 70, "RPC EPMAP"
	case 5900:
		return 85, "VNC 원격제어"
	case 23:
		return 100, "Telnet(평문)"
	case 21:
		return 90, "FTP(평문)"
	case 1433:
		return 80, "MS-SQL"
	case 5432:
		return 70, "PostgreSQL"
	case 3306:
		return 65, "MySQL"
	case 5985:
		return 70, "WinRM HTTP"
	case 5986:
		return 60, "WinRM HTTPS"
	case 22:
		return 55, "SSH"
	case 80:
		return 60, "HTTP"
	case 8080:
		return 55, "HTTP Alt"
	case 8443:
		return 45, "HTTPS Alt"
	case 443:
		return 35, "HTTPS"
	default:
		if port < 1024 {
			return 50, "Well-known 포트"
		}
		return 30, "임의 포트"
	}
}
func portsPenalty(open []int) int {
	pen := 0
	for _, p := range open {
		switch p {
		case 23:
			pen += 70
		case 21:
			pen += 60
		case 7547:
			pen += 30
		case 8080, 8443:
			pen += 15
		case 80:
			pen += 20
		case 22, 53:
			pen += 10
		case 443, 9443, 10443, 4443, 4433, 7001:
			pen += 0
		default:
			pen += 10
		}
	}
	if pen > 100 {
		pen = 100
	}
	return pen
}
func bucketPorts(pen int) int {
	switch {
	case pen >= 60:
		return 4
	case pen >= 40:
		return 3
	case pen >= 20:
		return 2
	case pen > 0:
		return 1
	default:
		return 0
	}
}

// ---------- Python ssl 기반 TLS 검사 ----------

func ensureTLSProbe() (string, error) {
	p := filepath.Join(os.TempDir(), "tls_probe.py")
	if _, err := os.Stat(p); err == nil {
		return p, nil
	}
	if err := os.WriteFile(p, []byte(tlsProbePy), 0600); err != nil {
		return "", err
	}
	return p, nil
}

// python 실행 파일/런처 자동 탐색
func pythonCmd() (string, []string) {
	if v := strings.TrimSpace(os.Getenv("PYTHON")); v != "" {
		return v, nil
	}
	candidates := [][]string{
		{"python"},
		{"py", "-3"},
		{"python3"},
	}
	for _, c := range candidates {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		args := append([]string{}, c[1]...)
		args = append(args, "-c", "import ssl; print('ok')")
		if err := exec.CommandContext(ctx, c[0], args...).Run(); err == nil {
			return c[0], c[1:]
		}
	}
	return "python", nil
}

func pythonTLS(host string, port int, sni string, verifyName string) TLSDiag {
	d := TLSDiag{Host: host, Port: port, ServerName: sni}
	path, err := ensureTLSProbe()
	if err != nil {
		d.Supported = false
		d.Reasons = append(d.Reasons, "tls_probe 준비 실패: "+err.Error())
		return d
	}
	exe, base := pythonCmd()
	args := append([]string{}, base...)
	args = append(args, path, "--host", host, "--port", strconv.Itoa(port), "--timeout", "3")
	if sni != "" {
		args = append(args, "--sni", sni)
	}
	if verifyName != "" {
		args = append(args, "--verify-name", verifyName)
	}

	ctx, cancel := context.WithTimeout(context.Background(), reqTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, exe, args...).CombinedOutput()
	if err != nil {
		d.Supported = false
		d.Reasons = append(d.Reasons, fmt.Sprintf("python 오류: %v; out=%s", err, strings.TrimSpace(string(out))))
		return d
	}

	var pj map[string]any
	if json.Unmarshal(out, &pj) != nil {
		d.Supported = false
		d.Reasons = append(d.Reasons, "python 출력 파싱 실패")
		return d
	}
	d.Supported = boolVal(pj["supported"])
	d.TLSVersion = fmt.Sprint(pj["version"])
	d.CipherSuite = fmt.Sprint(pj["cipher"])
	d.CertSubject = fmt.Sprint(pj["certSubject"])
	d.CertIssuer = fmt.Sprint(pj["certIssuer"])
	d.NotBefore = fmt.Sprint(pj["notBefore"])
	d.NotAfter = fmt.Sprint(pj["notAfter"])
	d.DaysLeft = intVal(pj["daysLeft"])
	d.ValidChain = boolVal(pj["validChain"])
	d.HostnameMatch = boolVal(pj["hostnameMatch"])
	d.SelfSigned = boolVal(pj["selfSigned"])
	if !d.Supported {
		if e := fmt.Sprint(pj["error"]); strings.TrimSpace(e) != "" && e != "<nil>" {
			d.Reasons = append(d.Reasons, e)
		}
	}
	applyTLSScore(&d, verifyName != "")
	return d
}
func boolVal(v any) bool { b, _ := v.(bool); return b }
func intVal(v any) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case int:
		return t
	default:
		i, _ := strconv.Atoi(fmt.Sprint(v))
		return i
	}
}
func applyTLSScore(d *TLSDiag, checkName bool) {
	score := 100
	switch d.TLSVersion {
	case "TLS1.3":
	case "TLS1.2":
		score -= 5
	default:
		if d.TLSVersion == "" {
			score -= 50
		} else {
			score -= 50
		}
		d.Reasons = append(d.Reasons, "낮은/미확인 TLS 버전")
	}
	u := strings.ToUpper(d.CipherSuite)
	if strings.Contains(u, "CBC") || strings.Contains(u, "RC4") {
		score -= 20
		d.Reasons = append(d.Reasons, "비권장 암호군")
	}
	if !d.ValidChain {
		score -= 40
	}
	if checkName && !d.HostnameMatch {
		score -= 15
	}
	if d.SelfSigned {
		score -= 30
	}
	if d.DaysLeft < 0 {
		score -= 60
	} else if d.DaysLeft < 30 {
		score -= 20
	}
	if score < 0 {
		score = 0
	}
	d.Score = score
}

// ---------- 망 용도 추정(폴백) ----------

func guessUse(scan ScanResult) UseGuess {
	var reasons []string
	ssidU := strings.ToUpper(scan.SSID)
	label := "unknown"
	conf := 40

	if regexp.MustCompile(`(?i)\b(POS|KIOSK|ORDER|STAFF|MACHINE|EMP|BACK|ADMIN)\b`).MatchString(ssidU) {
		reasons = append(reasons, "SSID 키워드 패턴")
		label = "kiosk"
		conf += 20
	}
	if scan.Auth == "WPA3-EAP" || scan.Auth == "WPA2-EAP" {
		reasons = append(reasons, "Enterprise(EAP) 인증")
		if label == "unknown" {
			label = "staff"
		}
		conf += 15
	}
	if scan.Auth == "OPEN" || scan.Auth == "OWE" {
		reasons = append(reasons, "인증없음/OWE")
		if label == "unknown" {
			label = "guest"
		}
	}
	if scan.Cipher == "TKIP" || scan.Cipher == "WEP" {
		reasons = append(reasons, "레거시 암호화")
		conf -= 10
	}
	if conf < 0 {
		conf = 0
	}
	if conf > 95 {
		conf = 95
	}
	return UseGuess{Label: label, Confidence: conf, Reasons: uniqueNonEmpty(reasons)}
}

// ---------- 위험지수/가중치 ----------

var wAuth, wCipher, wPMF, wPortal, wPorts = 0.40, 0.20, 0.20, 0.10, 0.10

func riskAuth(a string) int {
	switch a {
	case "WPA3-EAP":
		return 2
	case "WPA3-SAE":
		return 3
	case "WPA2-EAP":
		return 4
	case "WPA2-PSK":
		return 6
	case "OWE":
		return 7
	case "OPEN", "WEP":
		return 10
	default:
		return 6
	}
}
func riskCipher(c string) int {
	switch c {
	case "GCMP":
		return 2
	case "CCMP":
		return 3
	case "TKIP":
		return 8
	case "WEP", "NONE":
		return 10
	default:
		return 6
	}
}
func riskPMF(p string) int {
	switch p {
	case "required":
		return 0
	case "optional":
		return 3
	case "disabled":
		return 6
	default:
		return 2
	}
}
func riskPortal(cp string) int {
	switch cp {
	case "none":
		return 0
	case "suspected":
		return 2
	case "blocked":
		return 4
	default:
		return 2
	}
}

// ---------- 점수 계산 ----------

func score(input ScoreInput) ScoreResult {
	s := input.Scan
	var reasons, recs []string

	portal := captivePortalCheckMulti()
	gw := getDefaultGateway()
	var gwOpen []int
	if gw != "" {
		gwOpen = probeGatewayPorts(gw, gatewayPorts)
	}
	var gwDet []PortRisk
	for _, p := range gwOpen {
		rk, why := gatewayPortRisk(p)
		gwDet = append(gwDet, PortRisk{Port: p, Risk: rk, Reason: why})
	}
	sort.Slice(gwDet, func(i, j int) bool { return gwDet[i].Risk > gwDet[j].Risk })

	localListening := listLocalListening()
	var localDet []LocalPortRisk
	for _, x := range localListening {
		rk, why := localPortRisk(x.Port)
		localDet = append(localDet, LocalPortRisk{Address: x.Address, Port: x.Port, PID: x.PID, Risk: rk, Reason: why})
	}
	sort.Slice(localDet, func(i, j int) bool { return localDet[i].Risk > localDet[j].Risk })

	authP := pctAuth(s.Auth)
	ciphP := pctCipher(s.Cipher)
	pmfP := pctPMF(s.PMF)
	portP := 100 - portsPenalty(gwOpen)
	portalP := pctPortal(portal.Status)

	switch s.Auth {
	case "OPEN":
		reasons = append(reasons, "개방형 네트워크(암호화 없음)")
		recs = append(recs, "민감 업무 금지", "WPA3 또는 Enterprise SSID 사용")
	case "OWE":
		reasons = append(reasons, "OWE(Enhanced Open): 인증 없음")
		recs = append(recs, "민감 업무 시 VPN 권장")
	case "WPA2-PSK":
		reasons = append(reasons, "WPA2-Personal")
		recs = append(recs, "가능하면 WPA3 SSID 사용")
	case "WPA2-EAP":
		reasons = append(reasons, "WPA2-Enterprise(802.1X)")
		recs = append(recs, "가능하면 WPA3-Enterprise 전환")
	case "WPA3-SAE":
		reasons = append(reasons, "WPA3-Personal(SAE)")
	case "WPA3-EAP":
		reasons = append(reasons, "WPA3-Enterprise(802.1X)")
	case "WEP":
		reasons = append(reasons, "WEP 사용(취약)")
		recs = append(recs, "즉시 다른 SSID 사용 또는 교체 요청")
	default:
		reasons = append(reasons, "인증 방식 미확인")
	}
	if s.Cipher == "TKIP" {
		reasons = append(reasons, "TKIP 사용(취약)")
		recs = append(recs, "CCMP/GCMP 사용 SSID로 변경")
	}
	if s.Cipher == "WEP" {
		reasons = append(reasons, "WEP 암호화(취약)")
	}
	if portal.Status == "suspected" {
		reasons = append(reasons, "캡티브 포털/리디렉션 정황("+portal.From+")")
		recs = append(recs, "로그인/약관 완료 후 재평가")
	}
	if portal.Status == "blocked" {
		reasons = append(reasons, "외부 연결 제한/차단 정황")
		recs = append(recs, "네트워크 정책 확인 및 VPN 고려")
	}

	pen := portsPenalty(gwOpen)
	RI := float64(riskAuth(s.Auth))*wAuth +
		float64(riskCipher(s.Cipher))*wCipher +
		float64(riskPMF(s.PMF))*wPMF +
		float64(riskPortal(portal.Status))*wPortal +
		float64(bucketPorts(pen))*wPorts
	scoreVal := int(math.Round(100 - 10*RI))
	if (s.Auth == "OPEN" || s.Auth == "WEP" || s.Cipher == "WEP") && scoreVal > 40 {
		scoreVal = 40
	}
	if scoreVal < 0 {
		scoreVal = 0
	}
	if scoreVal > 100 {
		scoreVal = 100
	}
	level := "SAFE"
	switch {
	case scoreVal < 60:
		level = "RISK"
	case scoreVal < 80:
		level = "WARN"
	}

	// TLS: 게이트웨이(HTTPS 직접 + HTTP→HTTPS 추적), 포털(FQDN)
	var tlsGw []TLSDiag
	var noteGW string
	if gw != "" {
		for _, p := range gwOpen {
			if p == 443 || p == 8443 || p == 9443 || p == 10443 || p == 4443 || p == 4433 || p == 7001 {
				tlsGw = append(tlsGw, pythonTLS(gw, p, "", "")) // IP 대상, 이름검증 생략
			}
		}
		hasRow := len(tlsGw) > 0
		if !hasRow {
			httpPorts := []int{}
			for _, p := range gwOpen {
				if p == 80 || p == 8080 {
					httpPorts = append(httpPorts, p)
				}
			}
			if len(httpPorts) > 0 {
				found, note := discoverGatewayTLSViaHTTP(gw, httpPorts)
				if len(found) > 0 {
					tlsGw = append(tlsGw, found...)
				} else if noteGW == "" {
					noteGW = note
				}
			} else if noteGW == "" {
				noteGW = "게이트웨이 서비스 미탐지"
			}
		}
	}

	var tlsPortal *TLSDiag
	var notePT string
	if portal.Host != "" {
		d := pythonTLS(portal.Host, 443, portal.Host, portal.Host)
		tlsPortal = &d
	} else {
		switch portal.Status {
		case "none":
			notePT = "캡티브 포털 미감지"
		case "blocked":
			notePT = "리디렉션 FQDN 없음/차단"
		default:
			notePT = "포털 대상 정보 없음"
		}
	}

	// ScoreResult 조립
	sr := ScoreResult{
		Score:                  scoreVal,
		Level:                  level,
		Reasons:                uniqueNonEmpty(reasons),
		Recommendations:        uniqueNonEmpty(recs),
		CaptivePortal:          portal.Status,
		PortalHost:             portal.Host,
		Breakdown:              ScoreBreakdown{Auth: clamp01(authP), Cipher: clamp01(ciphP), PMF: clamp01(pmfP), Portal: clamp01(portalP), Ports: clamp01(portP)},
		Gateway:                gw,
		GatewayOpen:            gwOpen,
		GatewayOpenDetailed:    gwDet,
		LocalListening:         localListening,
		LocalListeningDetailed: localDet,
		TLS:                    TLSSummary{Gateway: tlsGw, Portal: tlsPortal, NoteGW: noteGW, NotePT: notePT},
	}

	// 망 용도 분류: DB 규칙 우선, 실패 시 폴백
	if gRules != nil {
		sr.UseGuess = classifyWithDB(gRules, s, sr)
	} else {
		sr.UseGuess = guessUse(s)
	}

	return sr
}

// 게이트웨이 HTTP→HTTPS 리디렉션 강화
func discoverGatewayTLSViaHTTP(gw string, httpPorts []int) (found []TLSDiag, note string) {
	client := &http.Client{
		Timeout: reqTimeout,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{Timeout: 1500 * time.Millisecond}).DialContext,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}

	// 포트 스캔에 안 잡혀도 한 번 더 찌를 후보
	guessTLS := []int{443, 8443, 9443, 10443, 4443, 4433, 7001}
	triedGuess := false

	for _, p := range httpPorts {
		addr := fmt.Sprintf("http://%s:%d/", gw, p)
		req, _ := http.NewRequest("GET", addr, nil)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		func() { defer resp.Body.Close() }()

		// 3xx Location 처리
		if resp.StatusCode/100 == 3 {
			loc := resp.Header.Get("Location")
			if loc != "" {
				if u, err := url.Parse(loc); err == nil {
					if strings.EqualFold(u.Scheme, "https") {
						host := u.Hostname()
						useHost := host
						if useHost == "" || isIP(host) {
							useHost = gw
						}
						usePort := 443
						if u.Port() != "" {
							if n, err := strconv.Atoi(u.Port()); err == nil {
								usePort = n
							}
						}
						d := pythonTLS(useHost, usePort,
							func() string { if isIP(useHost) { return "" } ; return host }(),
							func() string { if isIP(useHost) { return "" } ; return host }(),
						)
						found = append(found, d)
						continue
					}
					// 상대경로 or http 스킴 → 추측 포트 시도
					if !triedGuess {
						for _, gp := range guessTLS {
							d := pythonTLS(gw, gp, "", "")
							found = append(found, d)
						}
						triedGuess = true
					}
				}
			}
			continue
		}

		// 200 본문: https 링크 탐지
		if resp.StatusCode == 200 {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			body := string(b)
			if m := reHTTPSLink.FindString(body); m != "" {
				if u, err := url.Parse(m); err == nil {
					host := u.Hostname()
					useHost := host
					if useHost == "" || isIP(host) {
						useHost = gw
					}
					usePort := 443
					if u.Port() != "" {
						if n, err := strconv.Atoi(u.Port()); err == nil {
							usePort = n
						}
					}
					d := pythonTLS(useHost, usePort,
						func() string { if isIP(useHost) { return "" } ; return host }(),
						func() string { if isIP(useHost) { return "" } ; return host }(),
					)
					found = append(found, d)
					continue
				}
			}
			// 본문에도 없으면 추측 포트 시도(1회)
			if !triedGuess {
				for _, gp := range guessTLS {
					d := pythonTLS(gw, gp, "", "")
					found = append(found, d)
				}
				triedGuess = true
			}
		}
	}

	if len(found) == 0 {
		return nil, "HTTPS 관리 포트 미탐지(HTTP만 열림/비활성 또는 리디렉션 없음)"
	}
	return found, ""
}

// ---------- AI 요약(OpenAI / 로컬 폴백) ----------

type aiOut struct {
	Provider        string   `json:"provider"`
	ProviderSummary string   `json:"provider_summary"`
	UserSummary     string   `json:"user_summary"`
	KeyFindings     []string `json:"key_findings"`
	Recommendations []string `json:"recommendations"`
}

func summarizePrompt(rep Report) string {
	sc := rep.Scan
	gw := rep.Score.Gateway
	if gw != "" {
		gw = maskIPv4(gw)
	}
	var gwPorts []string
	for _, pr := range rep.Score.GatewayOpenDetailed {
		gwPorts = append(gwPorts, fmt.Sprintf("%d(%s)", pr.Port, pr.Reason))
	}
	if len(gwPorts) == 0 {
		gwPorts = []string{"없음"}
	}
	var tlsPortal string
	if rep.Score.TLS.Portal != nil {
		t := rep.Score.TLS.Portal
		tlsPortal = fmt.Sprintf("%s:%d %s/%s chain=%v nameMatch=%v exp=%s",
			t.Host, t.Port, t.TLSVersion, t.CipherSuite, t.ValidChain, t.HostnameMatch, t.NotAfter)
	}
	use := rep.Score.UseGuess

	return fmt.Sprintf(
		"다음 Wi-Fi 점검 결과를 JSON으로 요약하라. provider_summary, user_summary, key_findings[], recommendations[] 포함:\n"+
			"- SSID: %s, 인증: %s, 암호화: %s, PMF: %s, 채널: %d, 신호: %d%%\n"+
			"- 위험등급: %s, 점수: %d/100, 포털 상태: %s, 포털 호스트: %s\n"+
			"- 게이트웨이(IP 마스킹): %s, 오픈 포트: %s\n"+
			"- 포털 TLS: %s\n"+
			"- 망 용도 추정: %s(%d%%) 이유: %s\n"+
			"- 근거: %s\n- 권고: %s\n"+
			"간결하고 사실 위주로, 과장 금지.",
		emptyDash(sc.SSID), emptyDash(sc.Auth), emptyDash(sc.Cipher), emptyDash(sc.PMF), sc.Channel, sc.SignalPc,
		rep.Score.Level, rep.Score.Score, rep.Score.CaptivePortal, emptyDash(rep.Score.PortalHost),
		emptyDash(gw), strings.Join(gwPorts, ", "),
		emptyDash(tlsPortal),
		use.Label, use.Confidence, strings.Join(rep.Score.Reasons, "; "),
		strings.Join(rep.Score.Recommendations, "; "),
	)
}

func openAISummarize(ctx context.Context, prompt string) (string, error) {
	if strings.TrimSpace(openAIAPIKey) == "" {
		return "", errors.New("OPENAI_API_KEY not set")
	}
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"provider_summary": map[string]any{"type": "string"},
			"user_summary":     map[string]any{"type": "string"},
			"key_findings":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"recommendations":  map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		},
		"required":             []string{"provider_summary", "user_summary", "key_findings", "recommendations"},
		"additionalProperties": false,
	}
	body := map[string]any{
		"model": openAIModel,
		"input": prompt,
		"response_format": map[string]any{
			"type": "json_schema",
			"json_schema": map[string]any{
				"name":   "wifi_summary",
				"schema": schema,
				"strict": true,
			},
		},
	}
	b, _ := json.Marshal(body)
	u := strings.TrimRight(openAIHost, "/") + "/v1/responses"
	req, _ := http.NewRequestWithContext(ctx, "POST", u, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+openAIAPIKey)
	client := &http.Client{Timeout: reqTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		x, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("openai http %d: %s", resp.StatusCode, string(x))
	}
	var out struct {
		OutputText string `json:"output_text"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	return strings.TrimSpace(out.OutputText), nil
}

func localSummarizeJSON(rep Report) string {
	sc, sr := rep.Scan, rep.Score
	var kf []string
	kf = append(kf, fmt.Sprintf("인증=%s, 암호화=%s, PMF=%s", sc.Auth, sc.Cipher, sc.PMF))
	kf = append(kf, fmt.Sprintf("위험등급=%s, 점수=%d", sr.Level, sr.Score))
	if sr.CaptivePortal != "none" {
		kf = append(kf, "캡티브 포털 정황")
	}
	if len(sr.GatewayOpenDetailed) > 0 {
		kf = append(kf, fmt.Sprintf("게이트웨이 오픈 포트: %d개", len(sr.GatewayOpenDetailed)))
	}
	if sr.TLS.Portal != nil {
		kf = append(kf, fmt.Sprintf("포털 TLS: %s/%s", sr.TLS.Portal.TLSVersion, sr.TLS.Portal.CipherSuite))
	}
	prov := "게스트/업무망 분리, 관리 UI HTTPS 적용, WPA3/EAP 전환 검토"
	user := "민감업무 시 VPN 고려, 포털 오류 시 자격증명 입력 주의"
	out := map[string]any{
		"provider_summary": prov,
		"user_summary":     user,
		"key_findings":     kf,
		"recommendations":  sr.Recommendations,
	}
	b, _ := json.Marshal(out)
	return string(b)
}

// ---------- HTTP 서버 ----------

func main() {
	if runtime.GOOS != "windows" {
		log.Println("현재 OS:", runtime.GOOS, "(Windows 전용 경로/명령 사용)")
	}

	// 규칙 DB 초기화(실패해도 계속)
	var err error
	gRules, err = initRulesDB("") // exe 폴더\wifi_rules.db
	if err != nil {
		log.Println("rules db init error:", err)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		jsonWrite(w, map[string]any{"ok": true})
	})

	mux.HandleFunc("/report", func(w http.ResponseWriter, r *http.Request) {
		if runtime.GOOS != "windows" {
			http.Error(w, `{"error":"windows only"}`, http.StatusInternalServerError)
			return
		}
		s, err := scanWindows()
		if err != nil {
			http.Error(w, `{"error":"`+escapeJSON(err.Error())+`"}`, http.StatusInternalServerError)
			return
		}
		out := score(ScoreInput{Scan: *s})
		jsonWrite(w, Report{Scan: *s, Score: out})
	})

	mux.HandleFunc("/ai", func(w http.ResponseWriter, r *http.Request) {
		if runtime.GOOS != "windows" {
			http.Error(w, `{"error":"windows only"}`, http.StatusInternalServerError)
			return
		}
		s, err := scanWindows()
		if err != nil {
			http.Error(w, `{"error":"`+escapeJSON(err.Error())+`"}`, http.StatusInternalServerError)
			return
		}
		rep := Report{Scan: *s, Score: score(ScoreInput{Scan: *s})}
		prompt := summarizePrompt(rep)

		ctx, cancel := context.WithTimeout(r.Context(), reqTimeout)
		defer cancel()

		txt, err := openAISummarize(ctx, prompt)
		if err != nil || strings.TrimSpace(txt) == "" {
			txt = localSummarizeJSON(rep)
		}

		var parsed map[string]any
		if json.Unmarshal([]byte(txt), &parsed) == nil && parsed["provider_summary"] != nil {
			jsonWrite(w, aiOut{
				Provider:        func() string { if err == nil { return "openai" } ; return "local" }(),
				ProviderSummary: fmt.Sprint(parsed["provider_summary"]),
				UserSummary:     fmt.Sprint(parsed["user_summary"]),
				KeyFindings:     toStrSlice(parsed["key_findings"]),
				Recommendations: toStrSlice(parsed["recommendations"]),
			})
			return
		}
		jsonWrite(w, aiOut{
			Provider:        "local",
			ProviderSummary: txt,
			UserSummary:     "",
			KeyFindings:     rep.Score.Reasons,
			Recommendations: rep.Score.Recommendations,
		})
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		b, err := uiFS.ReadFile("ui.html")
		if err != nil {
			http.Error(w, "ui.html not found", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, string(b))
	})

	addr := "127.0.0.1:18080"
	log.Println("listening on http://" + addr)
	srv := &http.Server{Addr: addr, Handler: localOnly(mux)}
	log.Fatal(srv.ListenAndServe())
}

// ---------- helpers ----------

func localOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.Host)
		if host != "127.0.0.1" && host != "localhost" {
			http.Error(w, "local only", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
func jsonWrite(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
func toStrSlice(v any) []string {
	var out []string
	switch t := v.(type) {
	case []any:
		for _, e := range t {
			out = append(out, fmt.Sprint(e))
		}
	case []string:
		out = append(out, t...)
	}
	return out
}
