package core

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

type SiteTLS struct {
	CertificateID string `json:"certificate_id"`
	Redirect      bool   `json:"redirect"`
}
type Certificate struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Domains     []string `json:"domains"`
	Issuer      string   `json:"issuer"`
	Fingerprint string   `json:"fingerprint"`
	ChainSHA    string   `json:"chain_sha256"`
	NotBefore   string   `json:"not_before"`
	NotAfter    string   `json:"not_after"`
	Algorithm   string   `json:"algorithm"`
	Trusted     bool     `json:"trusted"`
	Status      string   `json:"status"`
	References  int      `json:"references"`
	CreatedAt   string   `json:"created_at"`
	PEM         string   `json:"-"`
}
type CertificateMaterial struct {
	ID             string `json:"id"`
	CertificatePEM string `json:"certificate_pem"`
	PrivateKeyPEM  string `json:"private_key_pem"`
}

// ParseCertificate accepts only a leaf-first certificate chain. It never returns private key material.
func ParseCertificate(certificatePEM, privateKeyPEM string, now time.Time) (Certificate, error) {
	var out Certificate
	if len(certificatePEM) > 32768 || len(privateKeyPEM) > 16384 || len(privateKeyPEM) == 0 {
		return out, errors.New("证书链或私钥大小不符合要求")
	}
	certs := []*x509.Certificate{}
	remaining := []byte(certificatePEM)
	canonical := []byte{}
	for len(bytes.TrimSpace(remaining)) > 0 {
		// pem.Decode may skip a text prefix; require an actual certificate block at the beginning.
		remaining = bytes.TrimSpace(remaining)
		if !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
			return out, errors.New("证书链只能包含 CERTIFICATE PEM 块")
		}
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return out, errors.New("证书链 PEM 格式无效")
		}
		cert, e := x509.ParseCertificate(block.Bytes)
		if e != nil {
			return out, errors.New("无法解析 X.509 证书")
		}
		certs = append(certs, cert)
		if len(certs) > 10 {
			return out, errors.New("证书链过长")
		}
		canonical = append(canonical, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes})...)
		remaining = rest
	}
	if len(certs) == 0 {
		return out, errors.New("请提供证书")
	}
	keyBytes := bytes.TrimSpace([]byte(privateKeyPEM))
	if !bytes.HasPrefix(keyBytes, []byte("-----BEGIN ")) {
		return out, errors.New("私钥 PEM 格式无效")
	}
	keyBlock, keyRest := pem.Decode(keyBytes)
	if keyBlock == nil || len(keyBlock.Headers) != 0 || len(bytes.TrimSpace(keyRest)) != 0 || (keyBlock.Type != "PRIVATE KEY" && keyBlock.Type != "RSA PRIVATE KEY" && keyBlock.Type != "EC PRIVATE KEY") {
		return out, errors.New("请提供单个未加密的 PEM 私钥")
	}
	pair, e := tls.X509KeyPair(canonical, keyBytes)
	if e != nil {
		return out, errors.New("证书与私钥不匹配，或私钥格式不被支持")
	}
	leaf := certs[0]
	if leaf.IsCA || len(leaf.DNSNames) == 0 {
		return out, errors.New("需提供包含域名的服务器叶证书")
	}
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return out, fmt.Errorf("证书尚未生效或已过期（检查时间 %s，有效期 %s 至 %s）", now.UTC().Format(time.RFC3339Nano), leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	validUsage := len(leaf.ExtKeyUsage) == 0
	for _, usage := range leaf.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth || usage == x509.ExtKeyUsageAny {
			validUsage = true
		}
	}
	if !validUsage {
		return out, errors.New("证书用途不允许服务器身份验证")
	}
	for i, cert := range certs {
		if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
			return out, fmt.Errorf("证书链第 %d 张尚未生效或已过期（检查时间 %s，有效期 %s 至 %s）", i+1, now.UTC().Format(time.RFC3339Nano), cert.NotBefore.UTC().Format(time.RFC3339), cert.NotAfter.UTC().Format(time.RFC3339))
		}
		if i+1 < len(certs) {
			if e = cert.CheckSignatureFrom(certs[i+1]); e != nil {
				return out, errors.New("证书链顺序或签名无效，请先放叶证书再放中间证书")
			}
		}
	}
	switch key := pair.PrivateKey.(type) {
	case *rsa.PrivateKey:
		if key.N.BitLen() < 2048 {
			return out, errors.New("RSA 私钥至少为 2048 位")
		}
		out.Algorithm = fmt.Sprintf("RSA %d", key.N.BitLen())
	case *ecdsa.PrivateKey:
		if key.Curve.Params().BitSize < 256 {
			return out, errors.New("ECDSA 曲线强度不足")
		}
		out.Algorithm = "ECDSA " + key.Curve.Params().Name
	case ed25519.PrivateKey:
		out.Algorithm = "Ed25519"
	default:
		return out, errors.New("不支持的私钥算法")
	}
	for _, domain := range leaf.DNSNames {
		d := strings.TrimPrefix(domain, "*.")
		if !ValidDomain(d) {
			return out, errors.New("证书域名格式不被支持")
		}
	}
	fingerprint := sha256.Sum256(leaf.Raw)
	chainSHA := sha256.Sum256(canonical)
	out.Domains = append([]string{}, leaf.DNSNames...)
	out.Issuer = leaf.Issuer.String()
	out.Fingerprint = hex.EncodeToString(fingerprint[:])
	out.ChainSHA = hex.EncodeToString(chainSHA[:])
	out.NotBefore = leaf.NotBefore.UTC().Format(time.RFC3339)
	out.NotAfter = leaf.NotAfter.UTC().Format(time.RFC3339)
	out.PEM = string(canonical)
	out.Status = "valid"
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}
	_, e = leaf.Verify(x509.VerifyOptions{CurrentTime: now, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	out.Trusted = e == nil
	return out, nil
}
func (c Certificate) ValidateDomains(primary string, additional []string, now time.Time) error {
	block, _ := pem.Decode([]byte(c.PEM))
	if block == nil {
		return errors.New("证书内容无效")
	}
	leaf, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		return errors.New("证书无法读取")
	}
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return errors.New("所选证书尚未生效或已过期")
	}
	for _, domain := range append([]string{primary}, additional...) {
		if e = leaf.VerifyHostname(domain); e != nil {
			return fmt.Errorf("证书未覆盖网站域名 %s", domain)
		}
	}
	return nil
}
