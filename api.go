package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/turing-complet/keymaker/keymaker"
)

var symmetricKeys = make(map[string][]byte)

type symmetricKey struct {
	ID  string
	Key []byte
}

func index(router *mux.Router) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode("Welcome to the secret cryptographic service 😎\n")
		router.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
			path, err := route.GetPathTemplate()
			if err != nil {
				return err
			}
			// fmt.Println(path)
			json.NewEncoder(w).Encode(path)
			// queriesTemplate, err := route.GetQueriesTemplates()
			// fmt.Println(queriesTemplate)
			return nil
		})
	}
}

func getUUID(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(keymaker.NewUUID())
}

func sha256Api(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	resp := keymaker.Sha256(params["data"], params["encoding"])
	json.NewEncoder(w).Encode(resp)
}

func sha512Api(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	resp := keymaker.Sha512(params["data"], params["encoding"])
	json.NewEncoder(w).Encode(resp)
}

func createSymmKey(w http.ResponseWriter, r *http.Request) {
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
		keyid := keymaker.NewUUID()
		symmetricKeys[keyid] = key
		resp := &symmetricKey{
			ID:  keyid,
			Key: key,
		}
		json.NewEncoder(w).Encode(resp)
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
	json.NewEncoder(w).Encode(hex.EncodeToString(ciphertext))
}

func aesDecrypt(w http.ResponseWriter, r *http.Request) {
	fmt.Println("doing decryption")
	params := mux.Vars(r)
	keyid := params["keyid"]
	ciphertext, _ := hex.DecodeString(params["ciphertext"])
	key, exists := symmetricKeys[keyid]
	if !exists {
		json.NewEncoder(w).Encode("Key not found.")
	}
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	if len(ciphertext) < gcm.NonceSize() {
		json.NewEncoder(w).Encode("malformed ciphertext")
	}
	plaintext, _ := gcm.Open(nil, ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():], nil)
	json.NewEncoder(w).Encode(string(plaintext))
}

func createRsaKey(w http.ResponseWriter, r *http.Request) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	json.NewEncoder(w).Encode(privKey)
}

func main() {
	router := mux.NewRouter()
	router.HandleFunc("/", index(router))
	router.HandleFunc("/uuid", getUUID)
	router.HandleFunc("/sha256/{data}", sha256Api).Queries("encoding", "{encoding}")
	router.HandleFunc("/sha512/{data}", sha512Api).Queries("encoding", "{encoding}")
	router.HandleFunc("/symmetrickeys", createSymmKey).Queries("bits", "{bits}").Methods("POST")
	router.HandleFunc("/symmetrickeys", listSymmKeys).Methods("GET")
	router.HandleFunc("/aes/encrypt/{plaintext}", aesEncrypt).Queries("keyid", "{keyid}")
	router.HandleFunc("/aes/decrypt/{ciphertext}", aesDecrypt).Queries("keyid", "{keyid}")
	router.HandleFunc("/rsa/keys", createRsaKey)
	// router.HandleFunc("/rsa/encrypt/{plaintext}", rsaEncrypt)
	// router.HandleFunc("/rsa/decrypt/{ciphertext}", rsaDecrypt)
	// router.HandleFunc("/rsa/sign/{message}", rsaSign)
	// router.HandleFunc("/rsa/verify/{message}/{signature}", rsaVerify)

	fmt.Println("Starting server on port 8080")

	log.Fatal(http.ListenAndServe(":8080", router))
}
