package keymaker

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"os/exec"
	"strings"
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
