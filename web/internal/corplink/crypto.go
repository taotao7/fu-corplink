package corplink

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// GenerateKeypair creates a fresh WireGuard x25519 keypair, returning the
// base64 (standard encoding) public and private keys. The private scalar is
// clamped per the curve25519 convention before the public key is derived.
func GenerateKeypair() (pub, priv string, err error) {
	var sk [32]byte
	if _, err = rand.Read(sk[:]); err != nil {
		return "", "", fmt.Errorf("generate private key: %w", err)
	}
	sk[0] &= 248
	sk[31] &= 127
	sk[31] |= 64
	pk, err := curve25519.X25519(sk[:], curve25519.Basepoint)
	if err != nil {
		return "", "", fmt.Errorf("derive public key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(pk), base64.StdEncoding.EncodeToString(sk[:]), nil
}

// PublicKeyFromPrivate derives the base64 public key from a base64 private key.
func PublicKeyFromPrivate(privateKey string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		return "", fmt.Errorf("decode private key: %w", err)
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("private key has invalid length %d", len(raw))
	}
	pk, err := curve25519.X25519(raw, curve25519.Basepoint)
	if err != nil {
		return "", fmt.Errorf("derive public key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(pk), nil
}

// b64DecodeToHex decodes a base64 (standard) string and re-encodes it as lower
// hex. Used to convert WireGuard keys into the hex form expected by the wg-go
// UAPI configuration protocol.
func b64DecodeToHex(s string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", fmt.Errorf("base64 decode %q: %w", s, err)
	}
	return hex.EncodeToString(data), nil
}

// b32Decode decodes an RFC4648 base32 (padded) string — the TOTP secret format.
func b32Decode(s string) ([]byte, error) {
	return base32.StdEncoding.DecodeString(s)
}

// sha256Hex returns the lower-hex sha256 of s, used by the corplink/ldap
// password login (the server stores the sha256 of the password).
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// feilianV1EncryptPassword reproduces the password encryption used by the
// official feilian client's v1 login (/api/v1/login), reverse-engineered from
// the Android client. Both AES key and IV are derived from fixed constants so
// the output is deterministic and acts as a stable server-side password hash:
//
//	KEY = hex(md5("9007199254740991"))   -> 32 ascii bytes (AES-256 key)
//	IV  = hex(sha1(KEY))[:16]            -> 16 ascii bytes
//	out = lower_hex( AES-256-CBC(KEY, IV, PKCS7(password)) )
func feilianV1EncryptPassword(password string) (string, error) {
	keySum := md5.Sum([]byte("9007199254740991"))
	key := []byte(hex.EncodeToString(keySum[:])) // 32 ascii bytes
	ivSum := sha1.Sum(key)
	iv := []byte(hex.EncodeToString(ivSum[:]))[:16]

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("aes cipher: %w", err)
	}
	plain := pkcs7Pad([]byte(password), block.BlockSize())
	out := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, plain)
	return hex.EncodeToString(out), nil
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	pad := blockSize - len(data)%blockSize
	out := make([]byte, len(data)+pad)
	copy(out, data)
	for i := len(data); i < len(out); i++ {
		out[i] = byte(pad)
	}
	return out
}

type androidModel struct {
	model   string
	release string
}

// A small pool of plausible Android device fingerprints reported to the server.
var androidModels = []androidModel{
	{model: "Xiaomi 14 Pro", release: "14"},
	{model: "Redmi K70 Pro", release: "14"},
	{model: "GooglePixel", release: "10"},
}

var androidPatchDates = []string{
	"2024-05-01",
	"2024-03-01",
	"2024-01-01",
}
