# GMTLS (SM2/SM3/SM4)

[![Go](https://github.com/xuweiguo/cnnic_gmtls/actions/workflows/go.yml/badge.svg)](https://github.com/xuweiguo/cnnic_gmtls/actions/workflows/go.yml)

纯 Go 实现的国密 TLS（含 TLS 1.3 GM 套件与 CNNIC EPP 客户端示例）。
算法内核统一使用 `github.com/emmansun/gmsm`，对外 API 保持 `gmtls` 自定义类型不变，便于迁移。

**特性**
- TLS 1.3 GM 套件（SM2/SM3/SM4）与会话恢复支持
- 兼容 Tongsuo/BabaSSL 的非标准握手细节
- CNNIC EPP 客户端示例与探测工具
- 支持服务端证书链验证与可选客户端证书认证

**互通策略（Tongsuo/BabaSSL）**
- TLS 1.3 套件优先 `0x00C6/0x00C7`，并兼容 `0x1306/0x1307`
- `key_share` 默认 `SM2`，可根据协商回退/切换到 `X25519`
- `signature_algorithms` 仅发送 `sm2sig_sm3`
- 客户端 `CertificateVerify` 使用 `HANDSHAKE_SM2_ID`
- 握手完成后的 `NewSessionTicket` 会缓存到 `Config.SessionTickets`

## 安装

```bash
go get github.com/xuweiguo/cnnic_gmtls
```

## 作为库使用

```go
import "github.com/xuweiguo/cnnic_gmtls"
```

建议使用 Go 1.21+。

## 快速开始

### CNNIC EPP 客户端

```bash
go run ./cmd/cnnic_epp -config cnnic/config.yml -action hello
```

参数说明：
- `-config`：配置文件路径（例如 `cnnic/config.yml`）
- `-action`：`hello`、`login` 或 `check`

### 其他命令

```bash
go run ./cmd/cnnic_probe
go run ./cmd/gmtls_demo
```

## 基本用法（类似 crypto/tls）

客户端：

```go
conn, err := gmtls.Dial("tcp", "example.com:443", &gmtls.Config{
	ServerName: "example.com",
	MaxVersion: gmtls.VersionTLS13,
})
```

服务端：

```go
cert, key, _ := gmtls.LoadX509KeyPair("server.crt", "server.key")
ln, err := gmtls.Listen("tcp", ":8443", &gmtls.Config{
	Certificates: []*gmtls.Certificate{cert},
	PrivateKey:   key,
})
```

## 使用示例

### TLS 1.3 会话恢复（客户端）

```go
cfg := &gmtls.Config{
	ServerName: "example.com",
	MaxVersion: gmtls.VersionTLS13,
	SessionTickets: []gmtls.TLS13SessionTicket{
		// 从本地缓存加载（由应用持久化）
	},
	OnNewSessionTicket: func(t gmtls.TLS13SessionTicket) {
		// 持久化票据，供下次恢复
	},
}
conn, err := gmtls.Dial("tcp", "example.com:443", cfg)
if err == nil {
	fmt.Println("resumed:", conn.ConnectionState().DidResume)
}
```

### 双证书（签名/加密分离）

```go
signCert, signKey, _ := gmtls.LoadX509KeyPair("sign.crt", "sign.key")
encCert, encKey, _ := gmtls.LoadX509KeyPair("enc.crt", "enc.key")

ln, err := gmtls.Listen("tcp", ":8443", &gmtls.Config{
	Certificates:     []*gmtls.Certificate{signCert},
	PrivateKey:       signKey,
	SignCertificates: []*gmtls.Certificate{signCert},
	SignPrivateKey:   signKey,
	EncCertificates:  []*gmtls.Certificate{encCert},
	EncPrivateKey:    encKey,
})
```

服务端校验客户端证书（TLS 1.3）：

```go
import "github.com/emmansun/gmsm/smx509"

clientCAPool := smx509.NewCertPool()
// clientCAPool.AddCert(...)

ln, err := gmtls.Listen("tcp", ":8443", &gmtls.Config{
	Certificates:     []*gmtls.Certificate{signCert},
	PrivateKey:       signKey,
	RequireClientCert: true,
	ClientCAs:         clientCAPool,
})
```

如果不启用 `RequireClientCert`，服务端仍可在握手后自行校验：

```go
import "github.com/emmansun/gmsm/smx509"

state := conn.ConnectionState()
if len(state.PeerCertificates) > 0 && state.PeerCertificates[0] != nil {
	certDER := state.PeerCertificates[0].Raw
	cert, _ := smx509.ParseCertificate(certDER)
	roots := smx509.NewCertPool()
	// roots.AddCert(...)
	_, err := cert.Verify(smx509.VerifyOptions{Roots: roots})
}
```

### SM2 签名/验签

```go
priv, pub, _ := gmtls.GenerateKey()
sig, _ := gmtls.SignMessage(priv, []byte("hello"))
ok := gmtls.VerifyMessage(pub, []byte("hello"), sig)
```

### SM4 加解密（ECB/CBC）

```go
key := []byte("1234567890abcdef")
iv := []byte("abcdef1234567890")

ct := gmtls.SM4Encrypt(key, []byte("secret"))
pt, _ := gmtls.SM4Decrypt(key, ct)

ct2 := gmtls.SM4EncryptCBC(key, iv, []byte("secret"))
pt2, _ := gmtls.SM4DecryptCBC(key, iv, ct2)
```

## 开发与测试

```bash
go test ./...
```

## 目录结构

- `cmd/cnnic_epp`：CNNIC EPP 客户端
- `cmd/cnnic_probe`：探测工具
- `cmd/gmtls_demo`：简易演示
- `cnnic/`：配置与示例证书
- `internal/legacy`：历史实现（仅保留参考，已通过 build tag 忽略）

## 安全提示

- `cnnic/gm/*.key` 仅用于示例，避免提交真实私钥
- 调整 TLS 默认值或套件选择时，请在此文档补充兼容性说明

## 已知限制与风险

- 当前实现仅支持 TLS 1.3；`MinVersion/MaxVersion` 与 TLS 1.2 相关配置不会生效。
- 客户端 `CipherSuites` 在 TLS 1.3 中固定为 `0x00C6/0x00C7` 优先（并兼容 `0x1306/0x1307`），不接受自定义顺序。
- 客户端 `key_share` 默认 `SM2`，在 `HelloRetryRequest` 时可能切换到 `X25519`。
- 若未配置 `RootCAs/ClientCAs`，证书链验证可能退化为系统默认或跳过（取决于 `InsecureSkipVerify`）。

## License

MIT
