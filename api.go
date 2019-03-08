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
	"log"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
)

func index(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode("Welcome to the secret cryptographic service 😎")
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
		key := make([]byte, bits)
		_, err = rand.Read(key)
		if err != nil {
			json.NewEncoder(w).Encode(err)
		} else {
			json.NewEncoder(w).Encode(key)
		}
	}
}

func aesEncrypt(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	key := []byte(params["key"])
	plaintext := []byte(params["plaintext"])
	nonce := make([]byte, 12)
	block, _ := aes.NewCipher(key)
	aesgcm, _ := cipher.NewGCM(block)
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	json.NewEncoder(w).Encode(ciphertext)

}

func createRsaKey(w http.ResponseWriter, r *http.Request) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	json.NewEncoder(w).Encode(privKey)
}

func main() {
	router := mux.NewRouter()
	router.HandleFunc("/", index)
	router.HandleFunc("/sha256/{data}", sha256Api).Methods("GET").Queries("encoding", "{encoding}")
	router.HandleFunc("/sha512/{data}", sha512Api)
	router.HandleFunc("/symmetrickey", createSymmKey).Queries("bits", "{bits}")
	router.HandleFunc("/rsa/keys", createRsaKey)
	router.HandleFunc("/aes/encrypt/{plaintext}", createRsaKey).Queries("key", "{key}")
	// router.HandleFunc("/rsa/encrypt/{plaintext}", rsaEncrypt)
	// router.HandleFunc("/rsa/decrypt/{ciphertext}", rsaDecrypt)
	// router.HandleFunc("/rsa/sign/{message}", rsaSign)
	// router.HandleFunc("/rsa/verify/{message}/{signature}", rsaVerify)

	log.Fatal(http.ListenAndServe(":8080", router))
}
