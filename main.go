package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/quic-go/quic-go/http3"
)

// 多協議服務器結構
type MultiProtocolServer struct {
	http3Server *http3.Server
	httpsServer *http.Server
	certFile    string
	keyFile     string
	http3Port   string
	httpsPort   string
}

// 中间件：日志记录
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// 创建响应写入器包装器来捕获状态码
		rw := &responseWriter{ResponseWriter: w, statusCode: 200}

		next.ServeHTTP(rw, r)

		duration := time.Since(start)
		log.Printf("[%s] %s %s %s %d %v",
			r.Proto, r.Method, r.URL.Path, r.RemoteAddr, rw.statusCode, duration)
	})
}

// 响应写入器包装器
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Alt-Svc 中间件：告知浏览器 HTTP/3 可用性
func altSvcMiddleware(http3Port string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 设置 Alt-Svc header 通知浏览器 HTTP/3 可用
			altSvc := fmt.Sprintf(`h3=":%s"; ma=86400`, http3Port)
			w.Header().Set("Alt-Svc", altSvc)

			next.ServeHTTP(w, r)
		})
	}
}

// 中间件：CORS 处理
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// 创建新的多协议服务器
func NewMultiProtocolServer(httpsPort, http3Port string) (*MultiProtocolServer, error) {
	s := &MultiProtocolServer{
		certFile:  "server.crt",
		keyFile:   "server.key",
		httpsPort: httpsPort,
		http3Port: http3Port,
	}

	// 生成或加载证书
	if err := s.ensureCertificates(); err != nil {
		return nil, fmt.Errorf("证书处理失败: %v", err)
	}

	// 加载 TLS 配置
	cert, err := tls.LoadX509KeyPair(s.certFile, s.keyFile)
	if err != nil {
		return nil, fmt.Errorf("加载证书失败: %v", err)
	}

	// HTTP/3 TLS 配置
	http3TLSConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h3"},
	}

	// HTTPS TLS 配置
	httpsTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
	}

	// 设置路由
	mux := s.setupRoutes()

	// 创建 HTTP/3 服务器
	s.http3Server = &http3.Server{
		Handler:   loggingMiddleware(corsMiddleware(mux)),
		Addr:      ":" + http3Port,
		TLSConfig: http3TLSConfig,
	}

	// 创建 HTTPS 服务器（带 Alt-Svc）
	httpsHandler := altSvcMiddleware(http3Port)(loggingMiddleware(corsMiddleware(mux)))
	s.httpsServer = &http.Server{
		Addr:      ":" + httpsPort,
		Handler:   httpsHandler,
		TLSConfig: httpsTLSConfig,
	}

	return s, nil
}

// 设置路由
func (s *MultiProtocolServer) setupRoutes() *http.ServeMux {
	mux := http.NewServeMux()

	// 静态文件服务
	mux.Handle("/static/", http.StripPrefix("/static/",
		http.FileServer(http.Dir("./static/"))))

	// API 路由
	mux.HandleFunc("/", s.handleHome)
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/api/info", s.handleInfo)
	mux.HandleFunc("/api/upload", s.handleUpload)
	mux.HandleFunc("/ws", s.handleWebSocket)

	return mux
}

// 首页处理器
func (s *MultiProtocolServer) handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// 根据协议显示不同的状态
	protocolStatus := "HTTPS (HTTP/1.1 或 HTTP/2)"
	protocolColor := "#ff9800"
	if r.Proto == "HTTP/3.0" || r.Proto == "HTTP/3" {
		protocolStatus = "HTTP/3 🚀"
		protocolColor = "#4caf50"
	}

	html := `<!DOCTYPE html>
<html>
<head>
    <title>多協議服務器 - HTTP/3 + HTTPS Fallback</title>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 1000px; margin: 0 auto; }
        .protocol-status { 
            background: ` + protocolColor + `; 
            color: white; 
            padding: 15px; 
            border-radius: 8px; 
            text-align: center;
            font-size: 18px;
            font-weight: bold;
            margin-bottom: 20px;
        }
        .info { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .api-list { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .feature-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        .feature-box { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .btn { background: #2196f3; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; display: inline-block; margin: 5px; }
        .btn:hover { background: #1976d2; }
        ul { list-style-type: none; padding: 0; }
        li { background: #f8f9fa; margin: 5px 0; padding: 10px; border-radius: 4px; border-left: 4px solid #2196f3; }
    </style>
    <script>
        // 检测协议支持情况
        function checkProtocolSupport() {
            const info = {
                protocol: '` + r.Proto + `',
                userAgent: navigator.userAgent,
                connection: navigator.connection ? navigator.connection.effectiveType : 'unknown'
            };
            console.log('連接信息:', info);
        }
        
        // 页面加载完成后执行
        window.onload = function() {
            checkProtocolSupport();
            
            // 显示协议切换提示
            if ('` + r.Proto + `' !== 'HTTP/3.0' && '` + r.Proto + `' !== 'HTTP/3') {
                setTimeout(() => {
                    console.log('當前使用 HTTPS，瀏覽器會自動嘗試升級到 HTTP/3');
                }, 1000);
            }
        }
    </script>
</head>
<body>
    <div class="container">
        <h1>🌐 多協議服務器</h1>
        
        <div class="protocol-status">
            當前連接協議: ` + protocolStatus + `
        </div>
        
        <div class="info">
            <h2>📊 連接詳情</h2>
            <p><strong>協議版本:</strong> ` + r.Proto + `</p>
            <p><strong>請求方法:</strong> ` + r.Method + `</p>
            <p><strong>服務器地址:</strong> ` + r.Host + `</p>
            <p><strong>客戶端 IP:</strong> ` + r.RemoteAddr + `</p>
            <p><strong>用戶代理:</strong> ` + r.UserAgent() + `</p>
        </div>
        
        <div class="api-list">
            <h2>📡 可用 API 端點</h2>
            <a href="/api/health" class="btn">健康檢查</a>
            <a href="/api/info" class="btn">服務器信息</a>
            <a href="/api/upload" class="btn">文件上傳測試</a>
        </div>
        
        <div class="feature-grid">
            <div class="feature-box">
                <h3>🚀 HTTP/3 特性</h3>
                <ul>
                    <li>基於 QUIC 協議</li>
                    <li>UDP 傳輸，更快的建立連接</li>
                    <li>內置 TLS 1.3 加密</li>
                    <li>多路復用，無隊頭阻塞</li>
                    <li>連接遷移支持</li>
                    <li>0-RTT 握手</li>
                </ul>
            </div>
            
            <div class="feature-box">
                <h3>🔄 自動 Fallback</h3>
                <ul>
                    <li>優先嘗試 HTTP/3 連接</li>
                    <li>不支持時自動降級到 HTTPS</li>
                    <li>透明的協議切換</li>
                    <li>兼容所有瀏覽器</li>
                    <li>Alt-Svc header 通知</li>
                    <li>無需用戶干預</li>
                </ul>
            </div>
        </div>
        
        <div class="info">
            <h3>💡 如何測試 HTTP/3</h3>
            <p><strong>Chrome:</strong> 開啟 chrome://flags/ 搜索 "HTTP/3" 並啟用</p>
            <p><strong>Firefox:</strong> 在 about:config 中設置 network.http.http3.enabled = true</p>
            <p><strong>Edge:</strong> 開啟 edge://flags/ 搜索 "HTTP/3" 並啟用</p>
            <p><strong>檢查方式:</strong> 開發者工具 → 網路標籤 → 查看協議欄</p>
        </div>
    </div>
</body>
</html>`

	fmt.Fprint(w, html)
}

// 健康检查处理器
func (s *MultiProtocolServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	isHTTP3 := r.Proto == "HTTP/3.0" || r.Proto == "HTTP/3"

	response := fmt.Sprintf(`{
    "status": "healthy",
    "protocol": "%s",
    "is_http3": %t,
    "timestamp": "%s",
    "uptime": "運行中",
    "ports": {
        "https": "%s",
        "http3": "%s"
    }
}`, r.Proto, isHTTP3, time.Now().Format(time.RFC3339), s.httpsPort, s.http3Port)

	fmt.Fprint(w, response)
}

// 服务器信息处理器
func (s *MultiProtocolServer) handleInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	info := fmt.Sprintf(`{
    "server": "Go 多協議服務器",
    "current_protocol": "%s",
    "supported_protocols": ["HTTP/3", "HTTP/2", "HTTP/1.1"],
    "quic_version": "支持最新版本",
    "tls_version": "TLS 1.3",
    "features": {
        "http3": [
            "QUIC 傳輸",
            "多路復用",
            "流量控制", 
            "連接遷移",
            "0-RTT 握手"
        ],
        "fallback": [
            "自動協議降級",
            "Alt-Svc 通知",
            "透明切換",
            "瀏覽器兼容"
        ]
    },
    "endpoints": [
        "/api/health",
        "/api/info",
        "/api/upload"
    ]
}`, r.Proto)

	fmt.Fprint(w, info)
}

// 文件上传处理器
func (s *MultiProtocolServer) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "僅支持 POST 方法", http.StatusMethodNotAllowed)
		return
	}

	// 限制上传大小为 10MB
	r.ParseMultipartForm(10 << 20)

	file, handler, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "文件上傳失敗: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	w.Header().Set("Content-Type", "application/json")

	response := fmt.Sprintf(`{
    "message": "文件上傳成功",
    "filename": "%s",
    "size": %d,
    "protocol": "%s",
    "upload_time": "%s"
}`, handler.Filename, handler.Size, r.Proto, time.Now().Format(time.RFC3339))

	fmt.Fprint(w, response)
}

// WebSocket 处理器
func (s *MultiProtocolServer) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "WebSocket 在 %s 協議中的處理方式有所不同\n", r.Proto)
	if r.Proto == "HTTP/3.0" || r.Proto == "HTTP/3" {
		fmt.Fprint(w, "HTTP/3 中建議使用 WebTransport 或 Server-Sent Events")
	} else {
		fmt.Fprint(w, "HTTPS 中可以正常使用 WebSocket")
	}
}

// 确保证书存在
func (s *MultiProtocolServer) ensureCertificates() error {
	if _, err := os.Stat(s.certFile); os.IsNotExist(err) {
		log.Println("證書不存在，生成自簽名證書...")
		return s.generateSelfSignedCert()
	}
	return nil
}

// 生成自签名证书
func (s *MultiProtocolServer) generateSelfSignedCert() error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Multi-Protocol Server"},
			Country:       []string{"TW"},
			Province:      []string{""},
			Locality:      []string{"Hsinchu"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:    []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	certFile, err := os.Create(s.certFile)
	if err != nil {
		return err
	}
	defer certFile.Close()

	pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyFile, err := os.Create(s.keyFile)
	if err != nil {
		return err
	}
	defer keyFile.Close()

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}

	pem.Encode(keyFile, &pem.Block{Type: "PRIVATE KEY", Bytes: privDER})

	log.Println("自簽名證書生成成功")
	return nil
}

// 启动服务器
func (s *MultiProtocolServer) Start() error {
	var wg sync.WaitGroup
	errChan := make(chan error, 2)

	// 启动 HTTPS 服务器
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Printf("🔒 HTTPS 服務器啟動在端口 %s", s.httpsPort)
		if err := s.httpsServer.ListenAndServeTLS(s.certFile, s.keyFile); err != http.ErrServerClosed {
			errChan <- fmt.Errorf("HTTPS 服務器錯誤: %v", err)
		}
	}()

	// 启动 HTTP/3 服务器
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Printf("🚀 HTTP/3 服務器啟動在端口 %s", s.http3Port)
		if err := s.http3Server.ListenAndServe(); err != nil {
			errChan <- fmt.Errorf("HTTP/3 服務器錯誤: %v", err)
		}
	}()

	log.Println("==========================================")
	log.Printf("📊 多協議服務器啟動成功")
	log.Printf("🔗 HTTPS 訪問: https://localhost:%s", s.httpsPort)
	log.Printf("🚀 HTTP/3 訪問: https://localhost:%s", s.http3Port)
	log.Println("💡 瀏覽器會自動選擇最佳協議")
	log.Println("==========================================")

	// 等待任一服务器出错
	select {
	case err := <-errChan:
		return err
	}
}

// 优雅关闭
func (s *MultiProtocolServer) Shutdown(ctx context.Context) error {
	log.Println("正在關閉服務器...")

	var wg sync.WaitGroup

	// 关闭 HTTPS 服务器
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.httpsServer.Shutdown(ctx); err != nil {
			log.Printf("HTTPS 服務器關閉錯誤: %v", err)
		}
	}()

	// 关闭 HTTP/3 服务器
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.http3Server.Close(); err != nil {
			log.Printf("HTTP/3 服務器關閉錯誤: %v", err)
		}
	}()

	wg.Wait()
	log.Println("所有服務器已關閉")
	return nil
}

func main() {
	// 创建多协议服务器
	// HTTPS 在 8443，HTTP/3 在 8444
	server, err := NewMultiProtocolServer("8443", "8444")
	if err != nil {
		log.Fatal("創建服務器失敗:", err)
	}

	// 设置优雅关闭
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			log.Printf("服務器關閉錯誤: %v", err)
		}
		os.Exit(0)
	}()

	// 启动服务器
	if err := server.Start(); err != nil {
		log.Fatal("服務器啟動失敗:", err)
	}
}
