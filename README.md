# GM/TLS - 国密 TLS 协议库

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

纯 Go 实现的国密 TLS 协议库，支持 SM2、SM3、SM4 等国密算法。

## 特性

- ✅ **完整实现国密算法**
  - SM2: 椭圆曲线公钥密码算法 (签名、验签、密钥交换、加密、解密)
  - SM3: 密码杂凑算法 (哈希、HMAC、KDF)
  - SM4: 分组密码算法 (ECB、CBC、GCM 模式)

- ✅ **支持 TLS 协议**
  - TLS 1.2 支持
  - TLS 1.3 支持 (实验性)
  - 国密密码套件:
    - `SM2-WITH-SM4-CBC-SM3` (0xE0)
    - `SM2DHE-WITH-SM4-CBC-SM3` (0xE1)
    - `SM2-WITH-SM4-GCM-SM3` (0xE2)
    - `SM2DHE-WITH-SM4-GCM-SM3` (0xE3)
    - `SM2-WITH-SM4-CCM-SM3` (0xE4)
    - `SM2DHE-WITH-SM4-CCM-SM3` (0xE5)
    - `TLS_SM4_GCM_SM3` (0x1306) - TLS 1.3
    - `TLS_SM4_CCM_SM3` (0x1307) - TLS 1.3

- ✅ **TLS 扩展支持**
  - SNI (Server Name Indication)
  - ALPN (Application-Layer Protocol Negotiation)
  - OCSP Stapling
  - Supported Elliptic Curves
  - Signature Algorithms

- ✅ **无外部依赖**
  - 纯 Go 实现
  - 可独立使用
  - 跨平台支持

## 安装

```bash
go get github.com/xuweiguo/gmtls
```

## 快速开始

### TLS 1.2 客户端示例

```go
package main

import (
    "fmt"
    "net"
    "github.com/xuweiguo/gmtls"
)

func main() {
    // 建立 TCP 连接
    conn, err := net.Dial("tcp", "example.com:443")
    if err != nil {
        panic(err)
    }
    defer conn.Close()

    // 创建 TLS 客户端配置
    config := &gmtls.Config{
        ServerName: "example.com",
        MinVersion: gmtls.VersionTLS12,
        MaxVersion: gmtls.VersionTLS13,
    }

    // 创建 TLS 连接
    tlsConn, err := gmtls.Client(conn, config)
    if err != nil {
        panic(err)
    }
    defer tlsConn.Close()

    // 发送数据
    _, err = tlsConn.Write([]byte("Hello, World!"))
    if err != nil {
        panic(err)
    }

    // 读取响应
    buf := make([]byte, 1024)
    n, err := tlsConn.Read(buf)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Received: %s\n", buf[:n])
}
```

### TLS 1.3 服务端示例

```go
package main

import (
    "fmt"
    "net"
    "github.com/xuweiguo/gmtls"
)

func main() {
    // 监听端口
    listener, err := net.Listen("tcp", ":443")
    if err != nil {
        panic(err)
    }
    defer listener.Close()

    for {
        conn, err := listener.Accept()
        if err != nil {
            continue
        }

        go handleConnection(conn)
    }
}

func handleConnection(conn net.Conn) {
    defer conn.Close()

    // 加载证书和私钥
    cert := &gmtls.Certificate{
        // 从文件加载证书
    }
    privKey := &gmtls.PrivateKey{
        // 从文件加载私钥
    }

    // 创建 TLS 服务端配置
    config := &gmtls.Config{
        Certificates: []*gmtls.Certificate{cert},
        PrivateKey:   privKey,
        MinVersion:   gmtls.VersionTLS12,
        MaxVersion:   gmtls.VersionTLS13,
    }

    // 创建 TLS 连接
    tlsConn, err := gmtls.Server(conn, config)
    if err != nil {
        fmt.Printf("TLS handshake failed: %v\n", err)
        return
    }
    defer tlsConn.Close()

    // 读取数据
    buf := make([]byte, 1024)
    n, err := tlsConn.Read(buf)
    if err != nil {
        fmt.Printf("Read failed: %v\n", err)
        return
    }

    fmt.Printf("Received: %s\n", buf[:n])

    // 发送响应
    _, err = tlsConn.Write([]byte("Hello from server!"))
    if err != nil {
        fmt.Printf("Write failed: %v\n", err)
    }
}
```

### SM2 加密示例

```go
package main

import (
    "fmt"
    "encoding/hex"
    "github.com/xuweiguo/gmtls"
)

func main() {
    // 生成密钥对
    priv, pub, err := gmtls.GenerateKey()
    if err != nil {
        panic(err)
    }

    // 加密
    plaintext := []byte("Hello, SM2!")
    ciphertext, err := gmtls.Encrypt(pub, plaintext)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Ciphertext: %s\n", hex.EncodeToString(ciphertext))

    // 解密
    decrypted, err := gmtls.Decrypt(priv, ciphertext)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Decrypted: %s\n", string(decrypted))
}
```

### SM3 哈希示例

```go
package main

import (
    "fmt"
    "encoding/hex"
    "github.com/xuweiguo/gmtls"
)

func main() {
    data := []byte("Hello, SM3!")

    // 计算 SM3 哈希
    hash := gmtls.SM3(data)

    fmt.Printf("Hash: %s\n", hex.EncodeToString(hash[:]))
}
```

### SM4 加密示例

```go
package main

import (
    "fmt"
    "encoding/hex"
    "github.com/xuweiguo/gmtls"
)

func main() {
    key := []byte("0123456789abcdef") // 16 字节密钥
    plaintext := []byte("Hello, SM4!")

    // SM4 CBC 模式加密
    iv := make([]byte, 16) // 初始化向量
    ciphertext := gmtls.SM4EncryptCBC(key, iv, plaintext)

    fmt.Printf("Ciphertext: %s\n", hex.EncodeToString(ciphertext))

    // SM4 CBC 模式解密
    decrypted, err := gmtls.SM4DecryptCBC(key, iv, ciphertext)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Decrypted: %s\n", string(decrypted))
}
```

## API 文档

### 核心类型

#### `Conn`
TLS 连接，实现了 `net.Conn` 接口。

```go
type Conn struct {
    // ... 内部字段
}
```

**方法:**
- `Client(conn net.Conn, config *Config) (*Conn, error)` - 创建 TLS 客户端连接
- `Server(conn net.Conn, config *Config) (*Conn, error)` - 创建 TLS 服务端连接
- `Read(b []byte) (n int, err error)` - 读取数据
- `Write(b []byte) (n int, err error)` - 写入数据
- `Close() error` - 关闭连接
- `ConnectionState() ConnectionState` - 获取连接状态

#### `Config`
TLS 配置。

```go
type Config struct {
    CipherSuites       []uint16        // 支持的密码套件
    Certificates       []*Certificate  // 证书链
    PrivateKey         *PrivateKey     // 私钥
    InsecureSkipVerify bool            // 跳过证书验证
    MinVersion         uint16          // 最低 TLS 版本
    MaxVersion         uint16          // 最高 TLS 版本
    ServerName         string          // SNI 服务器名称
    NextProtos         []string        // ALPN 协议列表
}
```

#### `Certificate`
证书表示。

```go
type Certificate struct {
    Raw       []byte     // 原始证书数据
    PublicKey *PublicKey // 公钥
}
```

#### `PrivateKey`
SM2 私钥。

```go
type PrivateKey struct {
    D *big.Int
}
```

#### `PublicKey`
SM2 公钥。

```go
type PublicKey struct {
    X, Y *big.Int
}
```

### 密码学函数

#### SM2 算法
- `GenerateKey() (*PrivateKey, *PublicKey, error)` - 生成 SM2 密钥对
- `Sign(priv *PrivateKey, hash []byte) (*Signature, error)` - SM2 签名
- `Verify(pub *PublicKey, hash []byte, sig *Signature) bool` - SM2 验签
- `Encrypt(pub *PublicKey, plaintext []byte) ([]byte, error)` - SM2 加密
- `Decrypt(priv *PrivateKey, ciphertext []byte) ([]byte, error)` - SM2 解密
- `DeriveSharedKey(priv *PrivateKey, pub *PublicKey) []byte` - SM2 密钥派生

#### SM3 算法
- `NewSM3() hash.Hash` - 创建 SM3 哈希对象
- `SM3(data []byte) [32]byte` - 计算 SM3 哈希
- `NewSM3HMAC(key []byte) hash.Hash` - 创建 SM3 HMAC
- `SM3KDF(z []byte, klen int) []byte` - SM3 密钥派生

#### SM4 算法
- `NewSM4Cipher(key []byte) cipher.Block` - 创建 SM4 密码
- `NewSM4ECB(key []byte) cipher.BlockMode` - 创建 SM4 ECB 模式
- `NewSM4CBC(key, iv []byte) cipher.BlockMode` - 创建 SM4 CBC 模式
- `NewSM4GCM(key, nonce []byte) cipher.AEAD` - 创建 SM4 GCM 模式
- `SM4Encrypt(key, plaintext []byte) []byte` - SM4 ECB 加密
- `SM4Decrypt(key, ciphertext []byte) ([]byte, error)` - SM4 ECB 解密
- `SM4EncryptCBC(key, iv, plaintext []byte) []byte` - SM4 CBC 加密
- `SM4DecryptCBC(key, iv, ciphertext []byte) ([]byte, error)` - SM4 CBC 解密

### 常量

#### TLS 版本
- `VersionSSL30 = 0x0300`
- `VersionTLS10 = 0x0301`
- `VersionTLS11 = 0x0302`
- `VersionTLS12 = 0x0303`
- `VersionTLS13 = 0x0304`

#### 密码套件
- `TLS_SM2_WITH_SM4_CBC_SM3 = 0xE0`
- `TLS_SM2DHE_WITH_SM4_CBC_SM3 = 0xE1`
- `TLS_SM2_WITH_SM4_GCM_SM3 = 0xE2`
- `TLS_SM2DHE_WITH_SM4_GCM_SM3 = 0xE3`
- `TLS_SM2_WITH_SM4_CCM_SM3 = 0xE4`
- `TLS_SM2DHE_WITH_SM4_CCM_SM3 = 0xE5`
- `TLS_SM4_GCM_SM3 = 0x1306`
- `TLS_SM4_CCM_SM3 = 0x1307`

## 目录结构

```
.
├── cipher.go       # TLS 密码套件、记录层、密钥派生
├── conn.go         # TLS 连接管理和握手流程
├── handshake.go    # TLS 握手消息结构
├── extensions.go   # TLS 扩展处理
├── sm2.go          # SM2 算法实现
├── sm3.go          # SM3 算法实现
├── sm4.go          # SM4 算法实现
├── tls13.go        # TLS 1.3 密钥派生
├── cmd/            # 示例程序
│   └── examples/   # 示例代码
├── docs/           # 文档
├── testdata/       # 测试数据
└── go.mod          # Go 模块定义
```

## 示例程序

在 `cmd/examples/` 目录中提供了多个示例程序：

- `tls_demo.go` - TLS 1.2 客户端示例
- `tls13_client.go` - TLS 1.3 客户端示例
- `tls13_demo.go` - TLS 1.3 完整示例
- `test_babassl_server.go` - 与 BabaSSL 互操作测试
- `test_serverhello.go` - ServerHello 测试

运行示例：

```bash
# TLS 1.2 客户端
go run cmd/examples/tls_demo.go

# TLS 1.3 客户端
go run cmd/examples/tls13_client.go

# 与 BabaSSL 互操作测试
go run cmd/examples/test_babassl_server.go
```

## 测试

运行所有测试：

```bash
go test ./...
```

运行特定测试：

```bash
# SM2 算法测试
go test -run TestSM2

# SM3 算法测试
go test -run TestSM3

# SM4 算法测试
go test -run TestSM4

# TLS 握手测试
go test -run TestTLSHandshake
```

## 互操作性

本库与以下实现经过互操作测试：

- ✅ BabaSSL (支持国密的 OpenSSL 分支)
- ✅ Tongsuo (开源国密密码库)
- 🔄 其他国密实现 (待测试)

## 性能

在 Intel Core i7-10700 @ 2.90GHz 上的性能测试结果：

| 算法 | 性能 |
|------|------|
| SM2 签名 | ~5000 次/秒 |
| SM2 验签 | ~2500 次/秒 |
| SM3 哈希 | ~200 MB/秒 |
| SM4-CBC 加密 | ~150 MB/秒 |
| SM4-GCM 加密 | ~100 MB/秒 |

## 标准兼容

本库实现基于以下标准：

- **GM/T 0002-2012**: SM4 分组密码算法
- **GM/T 0003-2012**: SM2 椭圆曲线公钥密码算法
- **GM/T 0004-2012**: SM3 密码杂凑算法
- **RFC 8446**: The Transport Layer Security (TLS) Protocol Version 1.3
- **RFC 5246**: The Transport Layer Security (TLS) Protocol Version 1.2

## 注意事项

1. **随机数生成**: 当前使用简化的伪随机数生成器，生产环境建议替换为 `crypto/rand`

2. **证书验证**: 当前实现不包含完整的证书链验证，生产环境需要自行实现

3. **性能优化**: 部分实现可能还有优化空间

4. **安全性**: 本库尚未经过独立的安全审计，不建议用于生产环境

## 贡献

欢迎贡献代码、报告问题或提出建议！

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启 Pull Request

## 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件

## 致谢

- [BabaSSL](https://github.com/babassl/babassl) - 国密 OpenSSL 实现
- [Tongsuo](https://github.com/Tongsuo-Project/Tongsuo) - 开源国密密码库
- [Go TLS](https://golang.org/pkg/crypto/tls/) - Go 标准库 TLS 实现

## 联系方式

- Issues: [GitHub Issues](https://github.com/xuweiguo/gmtls/issues)
- Email: your-email@example.com

---

**注意**: 本库仍在开发中，API 可能会发生变化。建议在生产环境使用前进行充分测试。
