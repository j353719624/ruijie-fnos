package main

// RUIJIE —— 飞牛 fnOS 上的锐捷（Ruijie EWeb）路由器管理应用。
//
// 后端职责：
//   1. 保存/读取路由器地址与账号（/var/apps/ruijie/var/config.json）
//   2. 登录锐捷 EWeb，读取概览与 ARP 终端表
//   3. 通过 fnOS 网关的 Unix Socket 提供 HTTP API，并托管 www/ 前端

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	appID          = "ruijie"
	defaultProbe   = 55557
	ruijieAcceptKey = "Web@Rj$2020!"
)

/* ------------------------------------------------------------------ */
/* 路径与环境                                                          */
/* ------------------------------------------------------------------ */

func appHome() string { return filepath.Join("/var/apps", appID) }

func socketPath() string {
	if p := os.Getenv("RUIJIE_HTTP_SOCKET_PATH"); p != "" {
		return p
	}
	return filepath.Join(appHome(), "target", appID)
}

func probePort() int {
	if v := os.Getenv("RUIJIE_PROBE_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return defaultProbe
}

func configPath() string {
	candidates := []string{
		filepath.Join(appHome(), "var", "config.json"),
	}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "..", "config", "router.json"))
	}
	candidates = append(candidates, "config.json")
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return candidates[0]
}

func wwwDir() string {
	if exe, err := os.Executable(); err == nil {
		for _, p := range []string{
			filepath.Join(filepath.Dir(exe), "www"),
			filepath.Join(filepath.Dir(exe), "..", "www"),
		} {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	return "www"
}

func logf(format string, args ...interface{}) {
	line := fmt.Sprintf("[%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), fmt.Sprintf(format, args...))
	path := filepath.Join(appHome(), "var", "ruijie.log")
	if f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err == nil {
		defer f.Close()
		f.WriteString(line)
	}
	log.Print(strings.TrimSpace(line))
}

/* ------------------------------------------------------------------ */
/* 配置                                                                */
/* ------------------------------------------------------------------ */

type routerConf struct {
	Host     string `json:"host"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func loadConf() routerConf {
	b, err := os.ReadFile(configPath())
	if err != nil {
		return routerConf{}
	}
	var c routerConf
	if json.Unmarshal(b, &c) != nil {
		return routerConf{}
	}
	if c.Username == "" {
		c.Username = "admin"
	}
	return c
}

func saveConf(c routerConf) error {
	p := configPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	return os.WriteFile(p, b, 0o600)
}

func normalizeHost(h string) string {
	h = strings.TrimSpace(h)
	if h == "" {
		return ""
	}
	if !strings.HasPrefix(h, "http://") && !strings.HasPrefix(h, "https://") {
		h = "http://" + h
	}
	return strings.TrimRight(h, "/")
}

/* ------------------------------------------------------------------ */
/* 锐捷 EWeb 客户端                                                     */
/* ------------------------------------------------------------------ */

type ruijieClient struct {
	host     string
	username string
	password string
	sid      string
	sn       string
	http     *http.Client
}

// gibberishAES 复刻 GibberishAES.enc：OpenSSL "Salted__" 格式，AES-256-CBC。
func gibberishAES(plain, pass string) (string, error) {
	salt := make([]byte, 8)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	p := []byte(pass)
	d1 := md5.Sum(append(append([]byte{}, p...), salt...))
	d2 := md5.Sum(append(append(append([]byte{}, d1[:]...), p...), salt...))
	key := append(append([]byte{}, d1[:]...), d2[:]...)
	ivFull := md5.Sum(append(append(append([]byte{}, d2[:]...), p...), salt...))
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	body := append([]byte(plain), bytes.Repeat([]byte{byte(pad)}, pad)...)
	out := make([]byte, len(body))
	cipher.NewCBCEncrypter(block, ivFull[:16]).CryptBlocks(out, body)
	raw := append(append([]byte("Salted__"), salt...), out...)
	return base64.StdEncoding.EncodeToString(raw), nil
}

func newCookieJar() http.CookieJar {
	jar, _ := cookiejar.New(nil)
	return jar
}

func newRuijieClient(host, user, pass string) *ruijieClient {
	// 同一网段有多块网卡时，固定出接口源 IP，避免设备把“取口令”和“登录”当成两个客户端。
	if ip := sourceIPFor(host); ip != nil {
		dialer := &net.Dialer{Timeout: 10 * time.Second, LocalAddr: &net.TCPAddr{IP: ip}}
		tr := &http.Transport{DialContext: dialer.DialContext, MaxIdleConnsPerHost: 2}
		return &ruijieClient{
			host: host, username: user, password: pass,
			http: &http.Client{Timeout: 12 * time.Second, Jar: newCookieJar(), Transport: tr},
		}
	}
	return &ruijieClient{
		host: host, username: user, password: pass,
		http: &http.Client{Timeout: 12 * time.Second, Jar: newCookieJar()},
	}
}

func sourceIPFor(host string) net.IP {
	h := host
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.IndexAny(h, "/:"); i >= 0 {
		h = h[:i]
	}
	conn, err := net.Dial("udp", h+":80")
	if err != nil {
		return nil
	}
	defer conn.Close()
	if a, ok := conn.LocalAddr().(*net.UDPAddr); ok && a.IP != nil {
		return a.IP
	}
	return nil
}

func (r *ruijieClient) base() string {
	return normalizeHost(r.host)
}

func (r *ruijieClient) loginKey() (string, error) {
	req, err := http.NewRequest("GET", r.base()+"/cgi-bin/luci/", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	res, err := r.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("无法打开登录页：%v", err)
	}
	defer res.Body.Close()
	page, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	re := regexp.MustCompile(`GibberishAES\.enc\(passwordEl\.value,\s*"([0-9a-fA-F]{32})"\)`)
	if m := re.FindSubmatch(page); len(m) > 1 {
		return string(m[1]), nil
	}
	return "", fmt.Errorf("登录页里没有找到加密口令")
}

func (r *ruijieClient) post(path string, body interface{}) ([]byte, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", r.base()+path, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0")
	// 设备只校验这个头：md5(固定前缀 + Content-Length)
	sum := md5.Sum([]byte(ruijieAcceptKey + fmt.Sprint(len(payload))))
	req.Header.Set("Content-Accept", hex.EncodeToString(sum[:]))
	req.Header.Set("Referer", r.base()+"/cgi-bin/luci/")
	if r.sid != "" {
		req.Header.Set("Cookie", r.sn+"="+r.sid)
	}
	res, err := r.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("设备返回 HTTP %d", res.StatusCode)
	}
	return out, nil
}

func (r *ruijieClient) Login() error {
	key, err := r.loginKey()
	if err != nil {
		return err
	}
	enc, err := gibberishAES(r.password, key)
	if err != nil {
		return err
	}
	body := map[string]interface{}{
		"method": "login",
		"params": map[string]interface{}{
			"username": r.username,
			"time":     fmt.Sprint(time.Now().Unix()),
			"encry":    true,
			"pwd":      enc,
		},
	}
	out, err := r.post("/cgi-bin/luci/api/auth", body)
	if err != nil {
		return err
	}
	var resp struct {
		Code int `json:"code"`
		Data *struct {
			Sid string `json:"sid"`
			Sn  string `json:"sn"`
			Msg string `json:"msg"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		return fmt.Errorf("登录响应无法解析")
	}
	if resp.Data == nil || resp.Data.Sid == "" {
		if resp.Data != nil && resp.Data.Msg != "" {
			return fmt.Errorf("登录失败：%s", resp.Data.Msg)
		}
		return fmt.Errorf("登录失败（密码错误，或失败次数过多已被临时锁定）")
	}
	r.sid = resp.Data.Sid
	r.sn = resp.Data.Sn
	if r.sn == "" {
		r.sn = "sid"
	}
	return nil
}

func (r *ruijieClient) Call(module, method string, params map[string]interface{}) (json.RawMessage, error) {
	if params == nil {
		params = map[string]interface{}{}
	}
	out, err := r.post("/cgi-bin/luci/api/"+module+"?auth="+r.sid, map[string]interface{}{
		"method": method, "params": params,
	})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Code int             `json:"code"`
		Data json.RawMessage `json:"data"`
		Msg  string          `json:"msg"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		return nil, fmt.Errorf("返回内容无法解析")
	}
	if resp.Code != 0 {
		return nil, fmt.Errorf("%s", orDefault(resp.Msg, "设备返回错误"))
	}
	return resp.Data, nil
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

/* ---- 会话缓存：避免重复登录（锐捷失败次数过多会临时锁定） ---- */

var (
	rjMu       sync.Mutex
	rjSessions = map[string]*ruijieClient{}
)

func ruijieSession(c routerConf) (*ruijieClient, error) {
	key := c.Host + "|" + c.Username
	rjMu.Lock()
	cl := rjSessions[key]
	rjMu.Unlock()
	if cl != nil && cl.sid != "" {
		return cl, nil
	}
	cl = newRuijieClient(c.Host, c.Username, c.Password)
	if err := cl.Login(); err != nil {
		return nil, err
	}
	rjMu.Lock()
	rjSessions[key] = cl
	rjMu.Unlock()
	return cl, nil
}

func dropRuijieSession(host string) {
	rjMu.Lock()
	for k := range rjSessions {
		if strings.HasPrefix(k, host+"|") {
			delete(rjSessions, k)
		}
	}
	rjMu.Unlock()
}

/* ------------------------------------------------------------------ */
/* 只读聚合                                                            */
/* ------------------------------------------------------------------ */

func routerInfo(c routerConf) (map[string]interface{}, error) {
	cl, err := ruijieSession(c)
	if err != nil {
		return nil, err
	}
	out := map[string]interface{}{"host": c.Host}
	if raw, err := cl.Call("overview", "getSysinfo", nil); err == nil {
		var m map[string]interface{}
		if json.Unmarshal(raw, &m) == nil {
			out["model"] = strOf(m["product_class"])
			out["firmware"] = strOf(m["software_version"])
			out["hardware"] = strOf(m["hardware_version"])
			out["vendor"] = strOf(m["manufacturer"])
			out["wan_ip"] = strOf(m["wan_ip"])
			out["mode"] = strOf(m["relayMode"])
		}
	}
	if raw, err := cl.Call("overview", "getHostName", nil); err == nil {
		var m map[string]interface{}
		if json.Unmarshal(raw, &m) == nil {
			out["hostname"] = strOf(m["hostname"])
		}
	}
	if raw, err := cl.Call("overview", "getDeviceInfo", nil); err == nil {
		var m map[string]interface{}
		if json.Unmarshal(raw, &m) == nil {
			out["uptime"] = numOf(m["uptime"])
			out["mem_used"] = numOf(m["mem_used"])
			out["mem_total"] = numOf(m["mem_total"])
			out["local_time"] = strOf(m["local_time"])
		}
	}
	return out, nil
}

func routerClients(c routerConf) ([]map[string]interface{}, error) {
	cl, err := ruijieSession(c)
	if err != nil {
		return nil, err
	}
	raw, err := cl.Call("network", "getArpTable", nil)
	if err != nil {
		return nil, err
	}
	var rows []map[string]interface{}
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, fmt.Errorf("终端列表解析失败")
	}
	out := make([]map[string]interface{}, 0, len(rows))
	for _, r := range rows {
		ip := strOf(r["ip"])
		if ip == "" {
			continue
		}
		out = append(out, map[string]interface{}{
			"ip": ip, "mac": strOf(r["mac"]),
			"interface": strOf(r["intf"]), "device": strOf(r["device"]),
		})
	}
	return out, nil
}

func strOf(v interface{}) string {
	switch x := v.(type) {
	case string:
		return x
	case nil:
		return ""
	default:
		b, _ := json.Marshal(x)
		return string(b)
	}
}

func numOf(v interface{}) float64 {
	if f, ok := v.(float64); ok {
		return f
	}
	return 0
}

/* ------------------------------------------------------------------ */
/* HTTP API                                                            */
/* ------------------------------------------------------------------ */

func writeJSON(w http.ResponseWriter, code int, message string, data interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]interface{}{"code": code, "message": message, "data": data})
}

func writeOK(w http.ResponseWriter, data interface{}) { writeJSON(w, 200, "操作成功", data) }
func writeErr(w http.ResponseWriter, msg string)      { writeJSON(w, 500, msg, nil) }

func routerAPI(w http.ResponseWriter, r *http.Request, path string) {
	conf := loadConf()
	action := strings.Trim(strings.TrimPrefix(path, "/api/router"), "/")
	if action == "" {
		action = "all"
	}

	switch action {
	case "config":
		if r.Method == http.MethodPost {
			var req routerConf
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeErr(w, "参数格式错误")
				return
			}
			req.Host = normalizeHost(req.Host)
			req.Username = strings.TrimSpace(req.Username)
			if req.Host == "" || req.Username == "" {
				writeErr(w, "请填写路由器地址和用户名")
				return
			}
			if req.Password == "" {
				req.Password = conf.Password
			}
			if req.Password == "" {
				writeErr(w, "请填写登录密码")
				return
			}
			dropRuijieSession(conf.Host)
			dropRuijieSession(req.Host)
			if err := saveConf(req); err != nil {
				writeErr(w, "保存配置失败："+err.Error())
				return
			}
			info, err := routerInfo(req)
			if err != nil {
				dropRuijieSession(req.Host)
				writeJSON(w, 200, "配置已保存，但连接失败："+err.Error(),
					map[string]interface{}{"saved": true, "connected": false, "message": err.Error(), "config": publicConf(req)})
				return
			}
			writeOK(w, map[string]interface{}{"saved": true, "connected": true, "config": publicConf(req), "info": info})
			return
		}
		writeOK(w, publicConf(conf))
		return

	case "test":
		if r.Method != http.MethodPost {
			writeErr(w, "请使用 POST")
			return
		}
		var req routerConf
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, "参数格式错误")
			return
		}
		req.Host = normalizeHost(req.Host)
		if req.Host == "" {
			writeErr(w, "请填写路由器地址")
			return
		}
		if req.Username == "" {
			req.Username = conf.Username
		}
		if req.Password == "" {
			req.Password = conf.Password
		}
		if req.Password == "" {
			writeErr(w, "请填写登录密码")
			return
		}
		cl := newRuijieClient(req.Host, req.Username, req.Password)
		if err := cl.Login(); err != nil {
			writeErr(w, "连接失败："+err.Error())
			return
		}
		rjMu.Lock()
		rjSessions[req.Host+"|"+req.Username] = cl
		rjMu.Unlock()
		info, err := routerInfo(req)
		if err != nil {
			writeErr(w, err.Error())
			return
		}
		writeOK(w, map[string]interface{}{"connected": true, "info": info})
		return

	case "info":
		if conf.Host == "" {
			writeErr(w, "尚未配置路由器")
			return
		}
		data, err := routerInfo(conf)
		if err != nil {
			dropRuijieSession(conf.Host)
			writeErr(w, err.Error())
			return
		}
		writeOK(w, data)

	case "clients":
		if conf.Host == "" {
			writeErr(w, "尚未配置路由器")
			return
		}
		data, err := routerClients(conf)
		if err != nil {
			dropRuijieSession(conf.Host)
			writeErr(w, err.Error())
			return
		}
		writeOK(w, data)

	case "all":
		if conf.Host == "" {
			writeErr(w, "尚未配置路由器")
			return
		}
		info, err := routerInfo(conf)
		if err != nil {
			dropRuijieSession(conf.Host)
			writeErr(w, err.Error())
			return
		}
		clients, _ := routerClients(conf)
		info["clients"] = clients
		info["client_count"] = len(clients)
		writeOK(w, info)

	default:
		writeErr(w, "未知操作："+action)
	}
}

func publicConf(c routerConf) map[string]interface{} {
	return map[string]interface{}{
		"host": c.Host, "username": c.Username,
		"has_password": c.Password != "",
	}
}

func handler(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		switch {
		case strings.HasPrefix(r.URL.Path, "/api/router"):
			routerAPI(w, r, r.URL.Path)
		case strings.HasSuffix(r.URL.Path, "/api/myip"):
			writeOK(w, map[string]string{"ip": clientIP(r)})
		default:
			writeErr(w, "未知接口")
		}
		return
	}
	if strings.HasSuffix(r.URL.Path, ".html") || strings.HasSuffix(r.URL.Path, ".js") || strings.HasSuffix(r.URL.Path, ".css") {
		w.Header().Set("Cache-Control", "no-cache")
	}
	http.FileServer(http.Dir(wwwDir())).ServeHTTP(w, r)
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

/* ------------------------------------------------------------------ */
/* 进程                                                                */
/* ------------------------------------------------------------------ */

func socketReady(p string) bool {
	fi, err := os.Stat(p)
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeSocket != 0
}

func serve() {
	sp := socketPath()
	_ = os.Remove(sp)
	if err := os.MkdirAll(filepath.Dir(sp), 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "mkdir:", err)
		os.Exit(1)
	}
	ln, err := net.Listen("unix", sp)
	if err != nil {
		fmt.Fprintln(os.Stderr, "listen unix:", err)
		os.Exit(1)
	}
	_ = os.Chmod(sp, 0o666)

	srv := &http.Server{Handler: http.HandlerFunc(handler)}
	go func() { _ = srv.Serve(ln) }()

	probe := &http.Server{Addr: fmt.Sprintf("0.0.0.0:%d", probePort()), Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		writeOK(w, map[string]string{"ip": clientIP(r)})
	})}
	go func() { _ = probe.ListenAndServe() }()

	logf("RUIJIE 已启动，socket=%s port=%d", sp, probePort())

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	<-sig
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	_ = probe.Shutdown(ctx)
	_ = srv.Close()
	_ = probe.Close()
	_ = os.Remove(sp)
}

func daemonize() {
	sp := socketPath()
	if socketReady(sp) {
		fmt.Println("already running")
		return
	}
	_ = os.MkdirAll(filepath.Dir(sp), 0o755)
	logPath := filepath.Join(appHome(), "var", "ruijie.log")
	_ = os.MkdirAll(filepath.Dir(logPath), 0o755)
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		logFile = os.Stdout
	}
	exe, err := os.Executable()
	if err != nil {
		exe = os.Args[0]
	}
	cmd := exec.Command(exe, "--serve")
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Stdin = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "start failed:", err)
		os.Exit(1)
	}
	_ = cmd.Process.Release()
	for i := 0; i < 150; i++ {
		if socketReady(sp) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	fmt.Fprintln(os.Stderr, "启动超时")
	os.Exit(1)
}

func main() {
	arg := "--status"
	if len(os.Args) > 1 {
		arg = os.Args[1]
	}
	switch arg {
	case "--status":
		if socketReady(socketPath()) {
			fmt.Println("Running")
			os.Exit(0)
		}
		fmt.Println("Stopped")
		os.Exit(3)
	case "--daemon":
		daemonize()
	case "--stop":
		os.Exit(0)
	default:
		serve()
	}
}
