# GMTLS (SM2/SM3/SM4)

纯 Go 实现的国密 TLS（含 TLS 1.3 GM 套件与 CNNIC EPP 客户端示例）。
算法内核已统一使用 `github.com/emmansun/gmsm`，对外 API 保持 `gmtls` 自定义类型不变。

## 互通说明（Tongsuo/BabaSSL）

为保证与 Tongsuo 服务端互通，默认行为：
- TLS 1.3 套件优先 `0x00C6/0x00C7`（并兼容 `0x1306/0x1307`）
- `key_share` 固定为 `SM2`
- `signature_algorithms` 仅发送 `sm2sig_sm3`
- 客户端 `CertificateVerify` 使用 `HANDSHAKE_SM2_ID`
- 握手完成后的 `NewSessionTicket` 会被解析并忽略，不影响应用层读取

## 实现说明

- 算法实现依赖 `github.com/emmansun/gmsm`（SM2/SM3/SM4），但保持 `gmtls.PrivateKey/PublicKey` 等类型不变，方便迁移。
- 保留非标准兼容路径（例如部分 CertificateVerify 变体）以提升与 Tongsuo/BabaSSL 的互通性。

### TLS 1.3 会话恢复（客户端）
- 可在 `Config.SessionTickets` 传入已保存的 `TLS13SessionTicket`
- 握手过程中收到的新票据可通过 `Config.OnNewSessionTicket` 回调持久化

## 安装

```bash
go get github.com/xuweiguo/cnnic_gmtls
```

## 快速开始

### CNNIC EPP 客户端

```bash
go run ./cmd/cnnic_epp -config cnnic/config.yml -action hello
```

参数说明：
- `-config`：配置文件路径（例如 `cnnic/config.yml`）
- `-action`：`hello` 或 `login`

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

## 使用方法

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

### TLS 1.2 客户端证书（服务端请求）

服务端开启客户端证书请求：

```go
cert, key, _ := gmtls.LoadX509KeyPair("server.crt", "server.key")
ln, err := gmtls.Listen("tcp", ":8443", &gmtls.Config{
	Certificates: []*gmtls.Certificate{cert},
	PrivateKey:   key,
	ClientAuth:   true,
})
```

客户端在服务端请求时自动发送证书：

```go
cert, key, _ := gmtls.LoadX509KeyPair("client.crt", "client.key")
conn, err := gmtls.Dial("tcp", "example.com:8443", &gmtls.Config{
	Certificates: []*gmtls.Certificate{cert},
	PrivateKey:   key,
})
```

#### 客户端证书链验证（服务端侧）

当前实现只验证客户端对私钥的持有（CertificateVerify），不自动验证证书链。
如需校验客户端证书合法性，可在握手完成后自行验证，例如：

```go
import "github.com/emmansun/gmsm/smx509"

state := conn.ConnectionState()
if len(state.PeerCertificates) > 0 && state.PeerCertificates[0] != nil {
	certDER := state.PeerCertificates[0].Raw
	cert, _ := smx509.ParseCertificate(certDER)
	// TODO: 构造根证书池与验证参数
	// _, err := cert.Verify(smx509.VerifyOptions{Roots: roots})
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

## 目录结构

- `cmd/cnnic_epp`：CNNIC EPP 客户端
- `cmd/cnnic_probe`：探测工具
- `cmd/gmtls_demo`：简易演示
- `internal/legacy`：历史实现（仅保留参考，已通过 build tag 忽略）

## License

MIT
