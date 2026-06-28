package gmtls

import (
	"bytes"
	"testing"
)

// TestRFC8998CertVerifyID 确证 RFC 8998/Tongsuo 的 CertificateVerify SM2 ID 规则。
//
// 背景:RFC 8998 §3.2.1 规定 TLS 1.3 CertificateVerify 消息的 SM2 签名使用
// HANDSHAKE_SM2_ID ("TLSv1.3+GM+Cipher+Suite"),而不是 X.509 证书验证用的
// CERTVRIFY_SM2_ID ("1234567812345678")。Tongsuo/BabaSSL 服务器在
// tls_construct_cert_verify 里通过 EVP_PKEY_CTX_set1_id 设置该 ID。
//
// 本测试模拟服务器用 HANDSHAKE ID 签名,确认只有用 HANDSHAKE ID 验签才能通过——
// 这正是 CNNIC 服务器 CertificateVerify 验签的根因(验签端错用了 CERTVRIFY ID)。
func TestRFC8998CertVerifyID(t *testing.T) {
	priv, pub, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	// 模拟 RFC 8446 CertificateVerify 待签名内容:
	//   64 * 0x20 || context || 0x00 || transcriptHash
	transcriptHash := SM3([]byte("fake transcript hash bytes here.."))
	signed := tls13CertVerifySigned("TLS 1.3, server CertificateVerify", transcriptHash[:])

	// 模拟 Tongsuo 服务器签名:用 HANDSHAKE_SM2_ID(ASN.1 DER 输出,与 Tongsuo 一致)。
	sigDER, err := sm2TLS13SignWithID(priv, signed, false, sm2TLS13HandshakeID())
	if err != nil {
		t.Fatalf("sm2TLS13SignWithID() error = %v", err)
	}

	// 验签:HANDSHAKE ID 必须通过。
	ok, err := sm2TLS13VerifyWithID(pub, signed, sigDER, sm2TLS13HandshakeID())
	if err != nil {
		t.Fatalf("verify with HANDSHAKE ID error = %v", err)
	}
	if !ok {
		t.Fatalf("verify with HANDSHAKE ID should succeed")
	}

	// 验签:CERTVRIFY ID("1234567812345678")必须失败——这正是 bug 路径。
	ok, err = sm2TLS13VerifyWithID(pub, signed, sigDER, sm2TLS13CertVerifyID())
	if err != nil {
		t.Fatalf("verify with CERTVRIFY ID error = %v", err)
	}
	if ok {
		t.Fatalf("verify with CERTVRIFY ID should FAIL but succeeded")
	}

	// 对称性:客户端 CertificateVerify 同理(已用 HANDSHAKE ID 签名)。
	clientSigned := tls13CertVerifySigned("TLS 1.3, client CertificateVerify", transcriptHash[:])
	clientSig, err := sm2TLS13SignWithID(priv, clientSigned, false, sm2TLS13HandshakeID())
	if err != nil {
		t.Fatalf("client sign error = %v", err)
	}
	ok, err = sm2TLS13VerifyWithID(pub, clientSigned, clientSig, sm2TLS13HandshakeID())
	if err != nil {
		t.Fatalf("client verify error = %v", err)
	}
	if !ok {
		t.Fatalf("client CertificateVerify verify with HANDSHAKE ID should succeed")
	}
}

// sanity: signed content 必须严格符合 RFC 8446 布局(64×0x20 + ctx + 0x00 + th)。
func TestTLS13CertVerifySignedLayout(t *testing.T) {
	ctx := "TLS 1.3, server CertificateVerify"
	th := SM3([]byte("x"))
	got := tls13CertVerifySigned(ctx, th[:])
	want := bytes.Repeat([]byte{0x20}, 64)
	want = append(want, ctx...)
	want = append(want, 0x00)
	want = append(want, th[:]...)
	if !bytes.Equal(got, want) {
		t.Fatalf("signed content layout mismatch")
	}
}
