package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os/exec"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
)

var symmetricKeys = make(map[string][]byte)

type symmetricKey struct {
	ID  string
	Key []byte
}

func index(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode("Welcome to the secret cryptographic service 😎")
}

func getUUID(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(newUUID())
}

func newUUID() string {
	uuid, _ := exec.Command("uuidgen").Output()
	// fmt.Printf("%s", uuid)
	return strings.TrimSuffix(string(uuid), "\n")

}

func sha256Api(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	sum := sha256.Sum256([]byte(params["data"]))
	switch params["encoding"] {
	case "bytes":
		json.NewEncoder(w).Encode(sum)
	case "hex":
		json.NewEncoder(w).Encode(hex.EncodeToString(sum[:]))
	}
}

func sha512Api(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	sum := sha512.Sum512([]byte(params["data"]))
	json.NewEncoder(w).Encode(sum)
}

func createSymmKey(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		json.NewEncoder(w).Encode("Use POST endpoint to create a symmetric key.")
	} else {
		params := mux.Vars(r)
		bits, err := strconv.Atoi(params["bits"])
		if err != nil {
			json.NewEncoder(w).Encode("Please specity bits as query string")
			return
		}
		key := make([]byte, bits/8)
		_, err = rand.Read(key)
		if err != nil {
			json.NewEncoder(w).Encode(err)
		} else {
			keyid := newUUID()
			symmetricKeys[keyid] = key
			resp := &symmetricKey{
				ID:  keyid,
				Key: key,
			}
			json.NewEncoder(w).Encode(resp)
		}
	}
}

// TODO: omit actual keys, persistence..
func listSymmKeys(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(symmetricKeys)
}

func aesEncrypt(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	keyid := params["keyid"]
	plaintext := []byte(params["plaintext"])
	key, exists := symmetricKeys[keyid]
	if !exists {
		json.NewEncoder(w).Encode("Key not found.")
	}
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	json.NewEncoder(w).Encode(ciphertext)
}

func aesDecrypt(w http.ResponseWriter, r *http.Request) {
	fmt.Println("doing decryption")
	params := mux.Vars(r)
	keyid := params["keyid"]
	fmt.Printf("ciphertext: %v", params["ciphertext"])
	ciphertext := []byte(params["ciphertext"])
	fmt.Printf("ciphertext_bytes: %v", ciphertext)
	key := symmetricKeys[keyid]
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	plaintext, _ := gcm.Open(nil, ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():], nil)
	json.NewEncoder(w).Encode(plaintext)
}

func createRsaKey(w http.ResponseWriter, r *http.Request) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	json.NewEncoder(w).Encode(privKey)
}

func main() {
	router := mux.NewRouter()
	router.HandleFunc("/", index)
	router.HandleFunc("/uuid", getUUID)
	router.HandleFunc("/sha256/{data}", sha256Api).Methods("GET").Queries("encoding", "{encoding}")
	router.HandleFunc("/sha512/{data}", sha512Api)
	router.HandleFunc("/symmetrickey", createSymmKey).Queries("bits", "{bits}")
	router.HandleFunc("/listkeys", listSymmKeys)
	router.HandleFunc("/aes/encrypt/{plaintext}", aesEncrypt).Queries("keyid", "{keyid}")
	router.HandleFunc("/aes/decrypt/{ciphertext}", aesDecrypt).Queries("keyid", "{keyid}")
	router.HandleFunc("/rsa/keys", createRsaKey)
	// router.HandleFunc("/rsa/encrypt/{plaintext}", rsaEncrypt)
	// router.HandleFunc("/rsa/decrypt/{ciphertext}", rsaDecrypt)
	// router.HandleFunc("/rsa/sign/{message}", rsaSign)
	// router.HandleFunc("/rsa/verify/{message}/{signature}", rsaVerify)

	log.Fatal(http.ListenAndServe(":8080", router))
}
