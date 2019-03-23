package keymaker

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"os/exec"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// NewUUID returns uuid
func NewUUID() string {
	uuid, _ := exec.Command("uuidgen").Output()
	// fmt.Printf("%s", uuid)
	return strings.TrimSuffix(string(uuid), "\n")
}

// Sha256 returns sha256
func Sha256(data string, encoding string) string {
	sum := sha256.Sum256([]byte(data))
	return encodeBytes(sum[:], encoding)
}

// Sha512 returns sha512
func Sha512(data string, encoding string) string {
	sum := sha512.Sum512([]byte(data))
	return encodeBytes(sum[:], encoding)
}

// Hmac computes hmac on data with given key
func Hmac(data []byte, key []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// ValidateHmac returns true if mac is valid given the data, key
func ValidateHmac(data []byte, mac []byte, key []byte) bool {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	expectedMAC := h.Sum(nil)
	return hmac.Equal(mac, expectedMAC)
}

// HashPassword generates a bcrypt hash of the password using work factor 14.
func HashPassword(password []byte) ([]byte, error) {
	return bcrypt.GenerateFromPassword(password, 14)
}

// CheckPasswordHash securely compares a bcrypt hashed password with its possible
// plaintext equivalent.  Returns nil on success, or an error on failure.
func CheckPasswordHash(hash, password []byte) error {
	return bcrypt.CompareHashAndPassword(hash, password)
}

func encodeBytes(data []byte, encoding string) string {
	switch encoding {
	case "bytes":
		return fmt.Sprintf("%s", data)
	case "numeric":
		return fmt.Sprintf("%d", data)
	case "hex":
		return hex.EncodeToString(data)
	default:
		return hex.EncodeToString(data)
	}
}
