package main

import (
	"context"
	"database/sql"
	_ "modernc.org/sqlite"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// ---- 규칙 메모리 구조 ----

type ruleset struct {
	ssid []struct{ re *regexp.Regexp; label string; w int }
	oui  []struct{ prefix string; label string; w int }
	gwp  []struct{ port int; label string; w int } // gateway ports
	lcl  []struct{ port int; label string; w int } // local listen ports
	tls  []struct{ re *regexp.Regexp; label string; w int } // TLS CN/Issuer
	misc []struct{ key, val, label string; w int }
	thr  map[string]int
}

// ---- DB 초기화/시드 ----

func initRulesDB(dbPath string) (*ruleset, error) {
	// 경로 결정: 비어 있으면 exe 폴더 아래 wifi_rules.db
	if strings.TrimSpace(dbPath) == "" {
		exe, _ := os.Executable()
		dir := filepath.Dir(exe)
		dbPath = filepath.Join(dir, "wifi_rules.db")
	}

	// SQLite 오픈
	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, err
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := createSchema(ctx, db); err != nil {
		return nil, fmt.Errorf("createSchema: %w", err)
	}
	if err := seedDefaults(ctx, db); err != nil {
		return nil, fmt.Errorf("seedDefaults: %w", err)
	}
	rs, err := loadRules(ctx, db)
	if err != nil {
		return nil, fmt.Errorf("loadRules: %w", err)
	}
	return rs, nil
}

func createSchema(ctx context.Context, db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS rule_ssid (
		   id INTEGER PRIMARY KEY,
		   pattern TEXT NOT NULL, label TEXT NOT NULL, weight INTEGER NOT NULL
		 );`,
		`CREATE TABLE IF NOT EXISTS rule_oui (
		   id INTEGER PRIMARY KEY,
		   oui_prefix TEXT NOT NULL, vendor TEXT, label TEXT NOT NULL, weight INTEGER NOT NULL
		 );`,
		`CREATE TABLE IF NOT EXISTS rule_port (
		   id INTEGER PRIMARY KEY,
		   direction TEXT NOT NULL, port INTEGER NOT NULL, label TEXT NOT NULL, weight INTEGER NOT NULL
		 );`,
		`CREATE TABLE IF NOT EXISTS rule_tls_cn (
		   id INTEGER PRIMARY KEY,
		   pattern TEXT NOT NULL, label TEXT NOT NULL, weight INTEGER NOT NULL
		 );`,
		`CREATE TABLE IF NOT EXISTS rule_misc (
		   id INTEGER PRIMARY KEY,
		   key TEXT NOT NULL, value TEXT NOT NULL, label TEXT NOT NULL, weight INTEGER NOT NULL
		 );`,
		`CREATE TABLE IF NOT EXISTS threshold (
		   label TEXT PRIMARY KEY, min_score INTEGER NOT NULL
		 );`,
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	for _, s := range stmts {
		if _, err := tx.ExecContext(ctx, s); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func tableCount(ctx context.Context, db *sql.DB, tbl string) (int, error) {
	var n int
	err := db.QueryRowContext(ctx, `SELECT COUNT(1) FROM `+tbl).Scan(&n)
	return n, err
}

func seedDefaults(ctx context.Context, db *sql.DB) error {
	// 이미 데이터가 있으면 스킵
	if n, _ := tableCount(ctx, db, "rule_ssid"); n == 0 {
		tx, _ := db.BeginTx(ctx, nil)
		// SSID 키워드 (정규식)
		_, _ = tx.ExecContext(ctx, `
INSERT INTO rule_ssid(pattern,label,weight) VALUES
 ('(?i)\\b(KIOSK|SELF\\s*ORDER|TABLE\\s*ORDER|ORDER\\b|POS\\b)','kiosk',30),
 ('(?i)\\b(STAFF|BACK\\s*OFFICE|ADMIN|EMP)\\b','staff',25),
 ('(?i)\\b(GUEST|FREE|PUBLIC|HOTSPOT|VISITOR)\\b','guest',25);`)
		_ = tx.Commit()
	}
	if n, _ := tableCount(ctx, db, "rule_port"); n == 0 {
		tx, _ := db.BeginTx(ctx, nil)
		// 게이트웨이 포트
		_, _ = tx.ExecContext(ctx, `
INSERT INTO rule_port(direction,port,label,weight) VALUES
 ('gateway',8080,'kiosk',10),
 ('gateway',8000,'kiosk',8),
 ('gateway',7547,'kiosk',10),
 ('gateway',8443,'kiosk',8);`)
		// 로컬 LISTEN 포트
		_, _ = tx.ExecContext(ctx, `
INSERT INTO rule_port(direction,port,label,weight) VALUES
 ('local',9100,'kiosk',10),
 ('local',515,'kiosk',8),
 ('local',8000,'kiosk',6),
 ('local',8081,'kiosk',6);`)
		_ = tx.Commit()
	}
	if n, _ := tableCount(ctx, db, "rule_tls_cn"); n == 0 {
		tx, _ := db.BeginTx(ctx, nil)
		// TLS 인증서 주체/발행자 키워드(일반 키워드 위주, 실제 벤더명은 현장 추가 권장)
		_, _ = tx.ExecContext(ctx, `
INSERT INTO rule_tls_cn(pattern,label,weight) VALUES
 ('(?i)\\b(KIOSK|POS|ORDER|CHECKOUT)\\b','kiosk',15),
 ('(?i)\\b(VERIFONE|INGENICO|PAX|SUNMI|ELO|NCR|NEWLAND|SHIJI)\\b','kiosk',12);`)
		_ = tx.Commit()
	}
	if n, _ := tableCount(ctx, db, "rule_misc"); n == 0 {
		tx, _ := db.BeginTx(ctx, nil)
		_, _ = tx.ExecContext(ctx, `
INSERT INTO rule_misc(key,value,label,weight) VALUES
 ('auth','WPA3-EAP','staff',20),
 ('auth','WPA2-EAP','staff',15),
 ('auth','OPEN','guest',25),
 ('auth','OWE','guest',15),
 ('auth','WPA2-PSK','guest',5),
 ('portal','suspected','guest',10),
 ('portal','none','kiosk',5);`)
		_ = tx.Commit()
	}
	if n, _ := tableCount(ctx, db, "threshold"); n == 0 {
		tx, _ := db.BeginTx(ctx, nil)
		_, _ = tx.ExecContext(ctx, `
INSERT INTO threshold(label,min_score) VALUES
 ('kiosk',60),('staff',60),('guest',50);`)
		_ = tx.Commit()
	}
	// rule_oui 는 현장 관측 후 추가 권장(초기값 비움)
	return nil
}

// ---- 규칙 로드 ----

func loadRules(ctx context.Context, db *sql.DB) (*ruleset, error) {
	rs := &ruleset{thr: map[string]int{}}

	// SSID
	{
		rows, err := db.QueryContext(ctx, `SELECT pattern,label,weight FROM rule_ssid`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			var p, l string
			var w int
			_ = rows.Scan(&p, &l, &w)
			re := regexp.MustCompile(p)
			rs.ssid = append(rs.ssid, struct {
				re    *regexp.Regexp
				label string
				w     int
			}{re, l, w})
		}
	}

	// OUI
	{
		rows, err := db.QueryContext(ctx, `SELECT oui_prefix,label,weight FROM rule_oui`)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var pref, l string
				var w int
				_ = rows.Scan(&pref, &l, &w)
				rs.oui = append(rs.oui, struct {
					prefix string
					label  string
					w      int
				}{strings.ToUpper(pref), l, w})
			}
		}
	}

	// Ports
	{
		rows, err := db.QueryContext(ctx, `SELECT direction,port,label,weight FROM rule_port`)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var dir, l string
				var p, w int
				_ = rows.Scan(&dir, &p, &l, &w)
				if dir == "gateway" {
					rs.gwp = append(rs.gwp, struct {
						port  int
						label string
						w     int
					}{p, l, w})
				} else if dir == "local" {
					rs.lcl = append(rs.lcl, struct {
						port  int
						label string
						w     int
					}{p, l, w})
				}
			}
		}
	}

	// TLS CN/Issuer
	{
		rows, err := db.QueryContext(ctx, `SELECT pattern,label,weight FROM rule_tls_cn`)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var p, l string
				var w int
				_ = rows.Scan(&p, &l, &w)
				rs.tls = append(rs.tls, struct {
					re    *regexp.Regexp
					label string
					w     int
				}{regexp.MustCompile(p), l, w})
			}
		}
	}

	// Misc
	{
		rows, err := db.QueryContext(ctx, `SELECT key,value,label,weight FROM rule_misc`)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var k, v, l string
				var w int
				_ = rows.Scan(&k, &v, &l, &w)
				rs.misc = append(rs.misc, struct {
					key   string
					val   string
					label string
					w     int
				}{k, v, l, w})
			}
		}
	}

	// Threshold
	{
		rows, err := db.QueryContext(ctx, `SELECT label,min_score FROM threshold`)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var l string
				var t int
				_ = rows.Scan(&l, &t)
				rs.thr[l] = t
			}
		}
	}

	return rs, nil
}

// ---- 도우미 ----

func ouiPrefix(bssid string) string {
	s := strings.ToUpper(strings.TrimSpace(bssid))
	parts := strings.Split(s, ":")
	if len(parts) >= 3 {
		return strings.Join(parts[:3], ":")
	}
	return ""
}

// ---- 분류 ----

func classifyWithDB(rs *ruleset, s ScanResult, sr ScoreResult) UseGuess {
	scores := map[string]int{"kiosk": 0, "staff": 0, "guest": 0}
	var reasons []string

	// SSID
	for _, r := range rs.ssid {
		if r.re.MatchString(s.SSID) {
			scores[r.label] += r.w
			reasons = append(reasons, "SSID:"+r.re.String())
		}
	}
	// OUI
	op := ouiPrefix(s.BSSID)
	for _, r := range rs.oui {
		if r.prefix == op {
			scores[r.label] += r.w
			reasons = append(reasons, "OUI:"+r.prefix)
		}
	}
	// 게이트웨이 포트
	for _, p := range sr.GatewayOpen {
		for _, r := range rs.gwp {
			if r.port == p {
				scores[r.label] += r.w
				reasons = append(reasons, fmt.Sprintf("GWPort:%d", p))
			}
		}
	}
	// 로컬 LISTEN 포트
	for _, l := range sr.LocalListening {
		for _, r := range rs.lcl {
			if r.port == l.Port {
				scores[r.label] += r.w
				reasons = append(reasons, fmt.Sprintf("Local:%d", l.Port))
			}
		}
	}
	// TLS CN/Issuer
	for _, d := range sr.TLS.Gateway {
		cn := d.CertSubject + " " + d.CertIssuer
		for _, r := range rs.tls {
			if r.re.MatchString(cn) {
				scores[r.label] += r.w
				reasons = append(reasons, "TLSCN:"+r.re.String())
			}
		}
	}
	if sr.TLS.Portal != nil {
		cn := sr.TLS.Portal.CertSubject + " " + sr.TLS.Portal.CertIssuer
		for _, r := range rs.tls {
			if r.re.MatchString(cn) {
				scores[r.label] += r.w
				reasons = append(reasons, "PortalCN:"+r.re.String())
			}
		}
	}
	// Misc (auth/cipher/portal)
	kv := map[string]string{"auth": s.Auth, "cipher": s.Cipher, "portal": sr.CaptivePortal}
	for _, r := range rs.misc {
		if kv[r.key] == r.val {
			scores[r.label] += r.w
			reasons = append(reasons, r.key+"="+r.val)
		}
	}

	// 결론
	best, second := "unknown", "unknown"
	b, sec := -1, -1
	for k, v := range scores {
		if v > b {
			second, sec = best, b
			best, b = k, v
		} else if v > sec {
			second, sec = k, v
		}
	}
	thr := rs.thr[best]
	if b < thr {
		return UseGuess{Label: "unknown", Confidence: 40, Reasons: uniqueNonEmpty(reasons)}
	}
	conf := int(math.Round(float64(100*b) / float64(b+sec+10)))
	if conf > 95 {
		conf = 95
	}
	return UseGuess{Label: best, Confidence: conf, Reasons: uniqueNonEmpty(reasons)}
}
