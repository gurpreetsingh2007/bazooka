package main

import (
	"bufio"
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
	"github.com/shirou/gopsutil/v4/process"
)

type app struct {
	token           string
	bad             map[string]failure
	mu              sync.Mutex
	dataMu          sync.RWMutex
	processRows     []processRow
	processWarnings []string
	systemStats     stats
	activeUntil     time.Time
	collecting      bool
}
type failure struct {
	count int
	until time.Time
}
type processPort struct {
	Port     uint32 `json:"port"`
	Scope    string `json:"scope"`
	Protocol string `json:"protocol"`
	State    string `json:"state,omitempty"`
}
type processRow struct {
	PID     int32         `json:"pid"`
	PPID    int32         `json:"ppid"`
	Name    string        `json:"name"`
	Source  string        `json:"source"`
	User    string        `json:"user"`
	Service string        `json:"service"`
	Exe     string        `json:"exe"`
	Cwd     string        `json:"cwd"`
	CPU     float64       `json:"cpu"`
	RSS     uint64        `json:"rss"`
	Threads int32         `json:"threads"`
	Ports   []processPort `json:"ports"`
	State   string        `json:"state"`
	Cmdline string        `json:"cmdline"`
}
type stats struct {
	CPU         float64   `json:"cpu"`
	MemoryUsed  uint64    `json:"memoryUsed"`
	MemoryTotal uint64    `json:"memoryTotal"`
	Load        []float64 `json:"load"`
	Uptime      uint64    `json:"uptime"`
	Count       int       `json:"count"`
}
type networkSnapshot struct {
	rows     []processRow
	warnings []string
	stats    stats
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
	go a.collectLoop()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200); _, _ = w.Write([]byte("ok")) })
	mux.HandleFunc("POST /api/login", a.login)
	mux.Handle("GET /api/session", a.auth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]bool{"authenticated": true})
	})))
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
	http.SetCookie(w, &http.Cookie{Name: "tm_token", Value: a.token, Path: "/", HttpOnly: true, Secure: requestIsSecure(r), SameSite: http.SameSiteStrictMode, MaxAge: 604800})
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func requestIsSecure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]), "https")
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
	a.touchCollector()
	a.dataMu.RLock()
	rows := a.processRows
	warnings := a.processWarnings
	a.dataMu.RUnlock()
	writeJSON(w, 200, map[string]any{"processes": rows, "warnings": warnings})
}

func (a *app) collectLoop() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		a.dataMu.RLock()
		active := time.Now().Before(a.activeUntil)
		a.dataMu.RUnlock()
		if active {
			a.startCollection()
		}
	}
}

func (a *app) touchCollector() {
	a.dataMu.Lock()
	a.activeUntil = time.Now().Add(8 * time.Second)
	a.dataMu.Unlock()
	a.startCollection()
}

func (a *app) startCollection() {
	a.dataMu.Lock()
	if a.collecting {
		a.dataMu.Unlock()
		return
	}
	a.collecting = true
	a.dataMu.Unlock()
	go func() {
		snapshot := collectSnapshot()
		a.dataMu.Lock()
		a.processRows, a.processWarnings, a.systemStats = snapshot.rows, snapshot.warnings, snapshot.stats
		a.collecting = false
		a.dataMu.Unlock()
	}()
}

func collectSnapshot() networkSnapshot {
	ps, err := process.Processes()
	if err != nil {
		return networkSnapshot{rows: []processRow{}, warnings: []string{"Unable to read host processes: " + err.Error()}}
	}
	portsByPID, warnings := hostPorts(ps)
	rows := make([]processRow, 0, len(ps))
	for _, p := range ps {
		row := processRow{PID: p.Pid, Ports: portsByPID[p.Pid]}
		if row.Ports == nil {
			row.Ports = []processPort{}
		}
		row.PPID, _ = p.Ppid()
		row.Name, _ = p.Name()
		row.User, _ = p.Username()
		row.Service, row.Source = processMetadata(p.Pid, row.Name, row.PPID)
		row.Exe, _ = p.Exe()
		row.Cwd, _ = p.Cwd()
		row.CPU, _ = p.CPUPercent()
		if m, e := p.MemoryInfo(); e == nil && m != nil {
			row.RSS = m.RSS
		}
		row.Threads, _ = p.NumThreads()
		state, _ := p.Status()
		row.State = strings.Join(state, ",")
		row.Cmdline, _ = p.Cmdline()
		rows = append(rows, row)
	}
	return networkSnapshot{rows: rows, warnings: warnings, stats: collectStats(len(rows))}
}

// hostPorts correlates socket file descriptors with the tables in each process's
// network namespace. This works with pid: host while preserving the container's network.
func hostPorts(ps []*process.Process) (map[int32][]processPort, []string) {
	portsByInode := make(map[string]map[processPort]struct{})
	pidsByInode := make(map[string]map[int32]struct{})
	netns := make(map[string]int32)
	for _, p := range ps {
		pid := p.Pid
		if target, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(int(pid)), "ns/net")); err == nil {
			if _, exists := netns[target]; !exists {
				netns[target] = pid
			}
		}
		fds, err := os.ReadDir(filepath.Join("/proc", strconv.Itoa(int(pid)), "fd"))
		if err != nil {
			continue
		}
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(int(pid)), "fd", fd.Name()))
			if err != nil || !strings.HasPrefix(target, "socket:[") {
				continue
			}
			inode := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
			if pidsByInode[inode] == nil {
				pidsByInode[inode] = make(map[int32]struct{})
			}
			pidsByInode[inode][pid] = struct{}{}
		}
	}
	var warnings []string
	for _, pid := range netns {
		for _, file := range []struct{ name, proto string }{{"tcp", "TCP"}, {"tcp6", "TCP"}, {"udp", "UDP"}, {"udp6", "UDP"}} {
			f, err := os.Open(filepath.Join("/proc", strconv.Itoa(int(pid)), "net", file.name))
			if err != nil {
				continue
			}
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				fields := strings.Fields(scanner.Text())
				if len(fields) < 10 || fields[0] == "sl" {
					continue
				}
				inode := fields[9]
				localParts := strings.Split(fields[1], ":")
				port, err := strconv.ParseUint(localParts[len(localParts)-1], 16, 16)
				if err != nil || port == 0 {
					continue
				}
				state := fields[3]
				stateLabel := ""
				if file.proto == "TCP" {
					stateLabel = tcpState(state)
				}
				item := processPort{Port: uint32(port), Scope: "local", Protocol: file.proto, State: stateLabel}
				if portsByInode[inode] == nil {
					portsByInode[inode] = make(map[processPort]struct{})
				}
				portsByInode[inode][item] = struct{}{}
				remoteParts := strings.Split(fields[2], ":")
				if len(remoteParts) > 1 {
					remotePort, remoteErr := strconv.ParseUint(remoteParts[len(remoteParts)-1], 16, 16)
					if remoteErr == nil && remotePort > 0 {
						item.Port, item.Scope = uint32(remotePort), "remote"
						portsByInode[inode][item] = struct{}{}
					}
				}
			}
			if err := scanner.Err(); err != nil {
				warnings = append(warnings, "Some network socket data could not be read: "+err.Error())
			}
			_ = f.Close()
		}
	}
	byPID := make(map[int32][]processPort)
	for inode, pids := range pidsByInode {
		for pid := range pids {
			for port := range portsByInode[inode] {
				byPID[pid] = append(byPID[pid], port)
			}
		}
	}
	for pid := range byPID {
		unique := make(map[processPort]struct{}, len(byPID[pid]))
		for _, port := range byPID[pid] {
			unique[port] = struct{}{}
		}
		byPID[pid] = byPID[pid][:0]
		for port := range unique {
			byPID[pid] = append(byPID[pid], port)
		}
		sort.Slice(byPID[pid], func(i, j int) bool {
			if byPID[pid][i].Port != byPID[pid][j].Port {
				return byPID[pid][i].Port < byPID[pid][j].Port
			}
			return byPID[pid][i].Protocol < byPID[pid][j].Protocol
		})
	}
	return byPID, warnings
}

func tcpState(code string) string {
	states := map[string]string{"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING"}
	return states[strings.ToUpper(code)]
}
func processMetadata(pid int32, fallback string, ppid int32) (string, string) {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(int(pid)), "cgroup"))
	if err != nil {
		if pid <= 2 || ppid == 2 {
			return fallback, "system"
		}
		return fallback, "host"
	}
	var scope string
	service := fallback
	group := strings.ToLower(string(data))
	source := "host"
	switch {
	case strings.Contains(group, "docker-") || strings.Contains(group, "/docker/"):
		source = "docker"
	case strings.Contains(group, "libpod"), strings.Contains(group, "podman"), strings.Contains(group, "containerd"), strings.Contains(group, "kubepods"):
		source = "container"
	case pid <= 2 || ppid == 2 || strings.Contains(group, "system.slice") || strings.Contains(group, "init.scope"):
		source = "system"
	}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		for _, part := range strings.Split(parts[2], "/") {
			if strings.HasSuffix(part, ".service") {
				service = strings.TrimSuffix(part, ".service")
			}
			if strings.HasSuffix(part, ".scope") {
				scope = strings.TrimSuffix(part, ".scope")
			}
		}
	}
	if scope != "" && !strings.HasPrefix(scope, "docker-") && !strings.HasPrefix(scope, "libpod-") {
		service = scope
	}
	return service, source
}
func (a *app) getStats(w http.ResponseWriter, _ *http.Request) {
	a.touchCollector()
	a.dataMu.RLock()
	out := a.systemStats
	a.dataMu.RUnlock()
	writeJSON(w, 200, out)
}
func collectStats(processCount int) stats {
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
	out.Count = processCount
	return out
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
