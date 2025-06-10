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
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/quic-go/quic-go/http3"
)

// HTTP/3 服务器结构
type HTTP3Server struct {
	server   *http3.Server
	certFile string
	keyFile  string
}

// 中间件：日志记录
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		
		// 创建响应写入器包装器来捕获状态码
		rw := &responseWriter{ResponseWriter: w, statusCode: 200}
		
		next.ServeHTTP(rw, r)
		
		duration := time.Since(start)
		log.Printf("%s %s %s %d %v",
			r.Method, r.URL.Path, r.Proto, rw.statusCode, duration)
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

// 创建新的 HTTP/3 服务器
func NewHTTP3Server(addr string) (*HTTP3Server, error) {
	s := &HTTP3Server{
		certFile: "server.crt",
		keyFile:  "server.key",
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
	
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h3"},
	}
	
	// 设置路由
	mux := s.setupRoutes()
	
	// 创建服务器
	s.server = &http3.Server{
		Handler:   loggingMiddleware(corsMiddleware(mux)),
		Addr:      addr,
		TLSConfig: tlsConfig,
	}
	
	return s, nil
}

// 设置路由
func (s *HTTP3Server) setupRoutes() *http.ServeMux {
	mux := http.NewServeMux()
	
	// 静态文件服务
	mux.Handle("/static/", http.StripPrefix("/static/", 
		http.FileServer(http.Dir("./static/"))))
	
	// API 路由
	mux.HandleFunc("/", s.handleHome)
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/api/info", s.handleInfo)
	mux.HandleFunc("/api/upload", s.handleUpload)
	mux.HandleFunc("/ws", s.handleWebSocket) // 注意：HTTP/3 中 WebSocket 的处理方式不同
	
	return mux
}

// 首页处理器
func (s *HTTP3Server) handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := `<!DOCTYPE html>
<html>
<head>
    <title>HTTP/3 Advanced Server</title>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .info { background: #f0f8ff; padding: 20px; border-radius: 8px; }
        .api-list { background: #f9f9f9; padding: 20px; border-radius: 8px; }
    </style>
</head>
<body>
    <h1>🚀 HTTP/3 高级服务器</h1>
    
    <div class="info">
        <h2>连接信息</h2>
        <p><strong>协议:</strong> ` + r.Proto + `</p>
        <p><strong>方法:</strong> ` + r.Method + `</p>
        <p><strong>地址:</strong> ` + r.Host + `</p>
        <p><strong>用户代理:</strong> ` + r.UserAgent() + `</p>
    </div>
    
    <div class="api-list">
        <h2>📡 可用 API</h2>
        <ul>
            <li><a href="/api/health">健康检查</a></li>
            <li><a href="/api/info">服务器信息</a></li>
            <li><a href="/api/upload">文件上传</a> (POST)</li>
        </ul>
    </div>
    
    <div class="info">
        <h2>🔧 HTTP/3 特性</h2>
        <ul>
            <li>基于 QUIC 协议，UDP 传输</li>
            <li>内置加密 (TLS 1.3)</li>
            <li>多路复用，无队头阻塞</li>
            <li>连接迁移支持</li>
            <li>0-RTT 握手</li>
        </ul>
    </div>
</body>
</html>`
	
	fmt.Fprint(w, html)
}

// 健康检查处理器
func (s *HTTP3Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	
	response := `{
    "status": "healthy",
    "protocol": "` + r.Proto + `",
    "timestamp": "` + time.Now().Format(time.RFC3339) + `",
    "uptime": "运行中"
}`
	
	fmt.Fprint(w, response)
}

// 服务器信息处理器
func (s *HTTP3Server) handleInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	info := `{
    "server": "Go HTTP/3 Server",
    "protocol": "` + r.Proto + `",
    "quic_version": "支持最新版本",
    "tls_version": "TLS 1.3",
    "features": [
        "多路复用",
        "流量控制", 
        "连接迁移",
        "0-RTT 握手"
    ],
    "endpoints": [
        "/api/health",
        "/api/info",
        "/api/upload"
    ]
}`
	
	fmt.Fprint(w, info)
}

// 文件上传处理器
func (s *HTTP3Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "仅支持 POST 方法", http.StatusMethodNotAllowed)
		return
	}
	
	// 限制上传大小为 10MB
	r.ParseMultipartForm(10 << 20)
	
	file, handler, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "文件上传失败: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()
	
	w.Header().Set("Content-Type", "application/json")
	
	response := `{
    "message": "文件上传成功",
    "filename": "` + handler.Filename + `",
    "size": ` + fmt.Sprintf("%d", handler.Size) + `,
    "protocol": "` + r.Proto + `"
}`
	
	fmt.Fprint(w, response)
}

// WebSocket 处理器 (HTTP/3 中的实现方式)
func (s *HTTP3Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// 注意：HTTP/3 中 WebSocket 的处理方式与 HTTP/1.1 和 HTTP/2 不同
	// 这里提供一个简单的替代方案
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, "HTTP/3 中 WebSocket 支持正在发展中，建议使用 Server-Sent Events 或其他方案")
}

// 确保证书存在
func (s *HTTP3Server) ensureCertificates() error {
	// 检查证书文件是否存在
	if _, err := os.Stat(s.certFile); os.IsNotExist(err) {
		log.Println("证书不存在，生成自签名证书...")
		return s.generateSelfSignedCert()
	}
	return nil
}

// 生成自签名证书
func (s *HTTP3Server) generateSelfSignedCert() error {
	// 生成私钥
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	
	// 创建证书模板
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Test Organization"},
			Country:       []string{"TW"},
			Province:      []string{""},
			Locality:      []string{"Hsinchu"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour), // 1年有效期
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:     []string{"localhost"},
	}
	
	// 生成证书
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}
	
	// 保存证书
	certFile, err := os.Create(s.certFile)
	if err != nil {
		return err
	}
	defer certFile.Close()
	
	pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	
	// 保存私钥
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
	
	log.Println("自签名证书生成成功")
	return nil
}

// 启动服务器
func (s *HTTP3Server) Start() error {
	log.Printf("HTTP/3 服务器启动在 %s", s.server.Addr)
	log.Println("支持协议: HTTP/3 (QUIC)")
	return s.server.ListenAndServe()
}

// 优雅关闭
func (s *HTTP3Server) Shutdown(ctx context.Context) error {
	log.Println("正在关闭服务器...")
	return s.server.Close()
}

func main() {
	// 创建服务器
	server, err := NewHTTP3Server(":8443")
	if err != nil {
		log.Fatal("创建服务器失败:", err)
	}
	
	// 设置优雅关闭
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("服务器关闭错误: %v", err)
		}
		os.Exit(0)
	}()
	
	// 启动服务器
	if err := server.Start(); err != nil {
		log.Fatal("服务器启动失败:", err)
	}
}