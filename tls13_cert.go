package gmtls

import (
	"encoding/binary"
	"errors"

	"github.com/emmansun/gmsm/smx509"
)

func marshalCertificateTLS13(cert *Certificate, context []byte) []byte {
	// TLS 1.3 Certificate: context (1 byte len) + context + cert_list_len(3)
	// certificate entry: cert_len(3) + cert + extensions_len(2)
	certList := cert.Chain
	if len(certList) == 0 && len(cert.Raw) > 0 {
		certList = [][]byte{cert.Raw}
	}
	totalEntriesLen := 0
	for _, c := range certList {
		totalEntriesLen += 3 + len(c) + 2
	}
	ctxLen := len(context)
	msgLen := 1 + ctxLen + 3 + totalEntriesLen

	data := make([]byte, 4+msgLen)
	data[0] = typeCertificate
	data[1] = byte(msgLen >> 16)
	data[2] = byte(msgLen >> 8)
	data[3] = byte(msgLen)

	off := 4
	if ctxLen > 255 {
		ctxLen = 255
		context = context[:ctxLen]
	}
	data[off] = byte(ctxLen) // certificate_request_context length
	off++
	if ctxLen > 0 {
		copy(data[off:off+ctxLen], context)
		off += ctxLen
	}

	// certificate_list length (3 bytes)
	data[off] = byte(totalEntriesLen >> 16)
	data[off+1] = byte(totalEntriesLen >> 8)
	data[off+2] = byte(totalEntriesLen)
	off += 3

	for _, c := range certList {
		certLen := len(c)
		// certificate entry length (3 bytes)
		data[off] = byte(certLen >> 16)
		data[off+1] = byte(certLen >> 8)
		data[off+2] = byte(certLen)
		off += 3
		copy(data[off:], c)
		off += certLen

		// extensions length (2 bytes) - empty
		binary.BigEndian.PutUint16(data[off:off+2], 0)
		off += 2
	}

	return data
}

func parseCertificateTLS13(data []byte) (*Certificate, error) {
	if len(data) < 4 || data[0] != typeCertificate {
		return nil, errors.New("gmtls: not a Certificate")
	}
	if len(data) < 5 {
		return nil, errors.New("gmtls: invalid Certificate")
	}

	off := 4
	ctxLen := int(data[off])
	off++
	if len(data) < off+ctxLen+3 {
		return nil, errors.New("gmtls: invalid Certificate context")
	}
	off += ctxLen

	listLen := int(data[off])<<16 | int(data[off+1])<<8 | int(data[off+2])
	off += 3
	if len(data) < off+listLen {
		return nil, errors.New("gmtls: invalid Certificate list length")
	}
	if listLen < 3 {
		return nil, errors.New("gmtls: empty Certificate list")
	}

	entriesEnd := off + listLen
	var chain [][]byte
	for off < entriesEnd {
		if entriesEnd-off < 3 {
			return nil, errors.New("gmtls: invalid Certificate entry length")
		}
		certLen := int(data[off])<<16 | int(data[off+1])<<8 | int(data[off+2])
		off += 3
		if entriesEnd-off < certLen+2 {
			return nil, errors.New("gmtls: invalid Certificate entry")
		}
		certRaw := make([]byte, certLen)
		copy(certRaw, data[off:off+certLen])
		off += certLen

		extLen := int(data[off])<<8 | int(data[off+1])
		off += 2
		if entriesEnd-off < extLen {
			return nil, errors.New("gmtls: invalid Certificate extensions")
		}
		off += extLen

		chain = append(chain, certRaw)
	}
	if len(chain) == 0 {
		return nil, errors.New("gmtls: empty Certificate list")
	}

	cert := &Certificate{Raw: chain[0], Chain: chain}
	if debugEnabled {
		debugf("DEBUG: Certificate chain entries=%d\n", len(chain))
		for i, der := range chain {
			if c, err := smx509.ParseCertificate(der); err == nil {
				debugf("DEBUG: Cert[%d] Subject=%s KeyUsage=0x%x ExtKeyUsage=%v\n", i, c.Subject.String(), c.KeyUsage, c.ExtKeyUsage)
			}
		}
	}
	if pub, err := ParseSM2PublicKeyFromCertificate(chain[0]); err == nil {
		cert.PublicKey = pub
	}
	return cert, nil
}

func parseCertificateRequestTLS13(data []byte) ([]byte, error) {
	if len(data) < 5 || data[0] != typeCertificateRequest {
		return nil, errors.New("gmtls: not a CertificateRequest")
	}
	off := 4
	ctxLen := int(data[off])
	off++
	if len(data) < off+ctxLen+2 {
		return nil, errors.New("gmtls: invalid CertificateRequest")
	}
	context := make([]byte, ctxLen)
	copy(context, data[off:off+ctxLen])
	// extensions length follows; ignore contents for now
	return context, nil
}
