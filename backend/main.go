package main

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"
	gnet "github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
)

type app struct {
	token string
	bad   map[string]failure
	mu    sync.Mutex
}
type failure struct {
	count int
	until time.Time
}
type processRow struct {
	PID     int32    `json:"pid"`
	PPID    int32    `json:"ppid"`
	Name    string   `json:"name"`
	User    string   `json:"user"`
	CPU     float64  `json:"cpu"`
	RSS     uint64   `json:"rss"`
	Threads int32    `json:"threads"`
	Ports   []uint32 `json:"ports"`
	State   string   `json:"state"`
	Cmdline string   `json:"cmdline"`
}
type stats struct {
	CPU         float64   `json:"cpu"`
	MemoryUsed  uint64    `json:"memoryUsed"`
	MemoryTotal uint64    `json:"memoryTotal"`
	Load        []float64 `json:"load"`
	Uptime      uint64    `json:"uptime"`
	Count       int       `json:"count"`
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		res, err := http.Get("http://127.0.0.1:" + env("PORT", "8080") + "/healthz")
		if err != nil || res.StatusCode != http.StatusOK {
			os.Exit(1)
		}
		os.Exit(0)
	}
	token := os.Getenv("TM_TOKEN")
	if strings.TrimSpace(token) == "" {
		log.Fatal("TM_TOKEN is required")
	}
	port := env("PORT", "8080")
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		log.Fatal("PORT must be a valid port number")
	}
	a := &app{token: token, bad: make(map[string]failure)}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200); _, _ = w.Write([]byte("ok")) })
	mux.HandleFunc("POST /api/login", a.login)
	mux.Handle("POST /api/logout", a.auth(http.HandlerFunc(a.logout)))
	mux.Handle("GET /api/processes", a.auth(http.HandlerFunc(a.processes)))
	mux.Handle("GET /api/stats", a.auth(http.HandlerFunc(a.getStats)))
	mux.Handle("POST /api/signal", a.auth(http.HandlerFunc(a.signal)))
	mux.Handle("/", http.FileServer(http.Dir("/web")))
	s := &http.Server{Addr: ":" + port, Handler: securityHeaders(mux), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second}
	log.Printf("Bazooka listening on :%s", port)
	log.Fatal(s.ListenAndServe())
}
func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
		}
		next.ServeHTTP(w, r)
	})
}
func (a *app) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		supplied := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if c, e := r.Cookie("tm_token"); supplied == "" && e == nil {
			supplied = c.Value
		}
		if len(supplied) != len(a.token) || subtle.ConstantTimeCompare([]byte(supplied), []byte(a.token)) != 1 {
			writeError(w, 401, "Authentication required")
			return
		}
		next.ServeHTTP(w, r)
	})
}
func (a *app) login(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	a.mu.Lock()
	f := a.bad[ip]
	if time.Now().Before(f.until) {
		wait := int(time.Until(f.until).Seconds()) + 1
		a.mu.Unlock()
		w.Header().Set("Retry-After", strconv.Itoa(wait))
		writeError(w, 429, "Too many failed logins; try again later")
		return
	}
	a.mu.Unlock()
	var body struct {
		Token string `json:"token"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body) != nil {
		writeError(w, 400, "Invalid request")
		return
	}
	if len(body.Token) != len(a.token) || subtle.ConstantTimeCompare([]byte(body.Token), []byte(a.token)) != 1 {
		a.mu.Lock()
		f = a.bad[ip]
		f.count++
		if f.count >= 5 {
			f.count = 0
			f.until = time.Now().Add(60 * time.Second)
		}
		a.bad[ip] = f
		a.mu.Unlock()
		writeError(w, 401, "Invalid token")
		return
	}
	a.mu.Lock()
	delete(a.bad, ip)
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "tm_token", Value: a.token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 86400})
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (a *app) logout(w http.ResponseWriter, _ *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "tm_token", Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func clientIP(r *http.Request) string {
	h, _, e := net.SplitHostPort(r.RemoteAddr)
	if e != nil {
		h = r.RemoteAddr
	}
	// Only accept proxy-supplied client addresses from local/private proxy networks;
	// direct internet clients cannot spoof X-Forwarded-For to evade throttling.
	addr := net.ParseIP(h)
	trustedProxy := addr != nil && (addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast())
	if trustedProxy {
		if x := r.Header.Get("X-Forwarded-For"); x != "" {
			return strings.TrimSpace(strings.Split(x, ",")[0])
		}
	}
	return h
}
func (a *app) processes(w http.ResponseWriter, _ *http.Request) {
	portsByPID := make(map[int32]map[uint32]struct{})
	if connections, err := gnet.Connections("all"); err == nil {
		for _, connection := range connections {
			if connection.Pid <= 0 || connection.Laddr.Port == 0 {
				continue
			}
			isTCPListener := connection.Type == uint32(syscall.SOCK_STREAM) && connection.Status == "LISTEN"
			isUDPPort := connection.Type == uint32(syscall.SOCK_DGRAM)
			if !isTCPListener && !isUDPPort {
				continue
			}
			if portsByPID[connection.Pid] == nil {
				portsByPID[connection.Pid] = make(map[uint32]struct{})
			}
			portsByPID[connection.Pid][connection.Laddr.Port] = struct{}{}
		}
	}
	ps, e := process.Processes()
	if e != nil {
		writeError(w, 500, "Unable to read /proc: "+e.Error())
		return
	}
	rows := make([]processRow, 0, len(ps))
	for _, p := range ps {
		row := processRow{PID: p.Pid}
		row.PPID, _ = p.Ppid()
		row.Name, _ = p.Name()
		row.User, _ = p.Username()
		row.CPU, _ = p.CPUPercent()
		if m, e := p.MemoryInfo(); e == nil && m != nil {
			row.RSS = m.RSS
		}
		row.Threads, _ = p.NumThreads()
		for port := range portsByPID[p.Pid] {
			row.Ports = append(row.Ports, port)
		}
		sort.Slice(row.Ports, func(i, j int) bool { return row.Ports[i] < row.Ports[j] })
		state, _ := p.Status()
		row.State = strings.Join(state, ",")
		row.Cmdline, _ = p.Cmdline()
		rows = append(rows, row)
	}
	writeJSON(w, 200, rows)
}
func (a *app) getStats(w http.ResponseWriter, _ *http.Request) {
	var out stats
	if v, e := cpu.Percent(0, false); e == nil && len(v) > 0 {
		out.CPU = v[0]
	}
	if m, e := mem.VirtualMemory(); e == nil {
		out.MemoryUsed = m.Used
		out.MemoryTotal = m.Total
	}
	if h, e := host.Info(); e == nil {
		out.Uptime = h.Uptime
	}
	if b, e := os.ReadFile("/proc/loadavg"); e == nil {
		f := strings.Fields(string(b))
		for i := 0; i < 3 && i < len(f); i++ {
			n, _ := strconv.ParseFloat(f[i], 64)
			out.Load = append(out.Load, n)
		}
	}
	if entries, e := os.ReadDir("/proc"); e == nil {
		for _, x := range entries {
			if _, e := strconv.Atoi(x.Name()); e == nil {
				out.Count++
			}
		}
	}
	writeJSON(w, 200, out)
}
func (a *app) signal(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PID      int32  `json:"pid"`
		Signal   string `json:"signal"`
		Children bool   `json:"children"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req) != nil {
		writeError(w, 400, "Invalid request")
		return
	}
	if req.PID <= 1 || req.PID == int32(os.Getpid()) {
		writeError(w, 403, "Refusing to signal PID 1 or Bazooka itself")
		return
	}
	sig, ok := map[string]syscall.Signal{"term": syscall.SIGTERM, "kill": syscall.SIGKILL, "stop": syscall.SIGSTOP, "cont": syscall.SIGCONT}[req.Signal]
	if !ok {
		writeError(w, 400, "Unsupported signal")
		return
	}
	pids := []int32{req.PID}
	if req.Children {
		pids = descendants(req.PID)
	}
	var errs []string
	succeeded := 0
	for i := len(pids) - 1; i >= 0; i-- {
		pid := pids[i]
		if pid <= 1 || pid == int32(os.Getpid()) {
			continue
		}
		e := syscall.Kill(int(pid), sig)
		if e == nil {
			succeeded++
		} else if errors.Is(e, syscall.ESRCH) {
			errs = append(errs, fmt.Sprintf("PID %d already exited", pid))
		} else if errors.Is(e, syscall.EPERM) {
			errs = append(errs, fmt.Sprintf("Permission denied for PID %d", pid))
		} else {
			errs = append(errs, fmt.Sprintf("PID %d: %v", pid, e))
		}
	}
	if succeeded == 0 {
		status := 400
		for _, e := range errs {
			if strings.Contains(e, "Permission denied") {
				status = 403
			}
		}
		writeJSON(w, status, map[string]any{"ok": false, "message": strings.Join(errs, "; ")})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "message": fmt.Sprintf("Signal sent to %d process(es)", succeeded), "errors": errs})
}
func descendants(root int32) []int32 {
	all := map[int32]int32{}
	entries, _ := os.ReadDir("/proc")
	for _, e := range entries {
		n, err := strconv.ParseInt(e.Name(), 10, 32)
		if err != nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join("/proc", e.Name(), "stat"))
		if err != nil {
			continue
		}
		s := string(b)
		i := strings.LastIndex(s, ")")
		if i < 0 {
			continue
		}
		f := strings.Fields(s[i+1:])
		if len(f) > 1 {
			p, _ := strconv.ParseInt(f[1], 10, 32)
			all[int32(n)] = int32(p)
		}
	}
	out := []int32{root}
	seen := map[int32]bool{root: true}
	for changed := true; changed; {
		changed = false
		for pid, ppid := range all {
			if seen[ppid] && !seen[pid] {
				seen[pid] = true
				out = append(out, pid)
				changed = true
			}
		}
	}
	return out
}
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
