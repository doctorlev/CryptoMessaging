package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/spacemonkeygo/openssl"
)

// EncryptRequest structure - for encryption
type EncryptRequest struct {
	Text string `json:"text"`
	Pass string `json:"pass"`
}

// EncryptedResponse structure -  will be inserted into formed O/G Request after encryption
type EncryptedResponse struct {
	Hash string    `json:"hash"`
	Time time.Time `json:"time"`
}

// DecryptRequest structure - for encryption
type DecryptRequest struct {
	Hash string `json:"hash"`
	Pass string `json:"pass"`
}

// DecryptedResponse structure -  will be inserted into formed O/G Request after decryption
type DecryptedResponse struct {
	Text string    `json:"text"`
	Time time.Time `json:"time"`
}

// Crypter ...a structure, represents the "key", "iv" in bytes and cipher
type Crypter struct {
	key    []byte
	iv     []byte
	cipher *openssl.Cipher
}

// NewCrypter ... openSSL crypter aes-256-cbc, returns key, iv, cipher
// to put the values using the pointer to Crypter structure
func NewCrypter(key []byte, iv []byte) (*Crypter, error) {
	cipher, err := openssl.GetCipherByName("aes-256-cbc")
	if err != nil {
		return nil, err
	}

	return &Crypter{key, iv, cipher}, nil
}

// Encrypt - this is  METHOD for the structure 'Crypter'
func (c *Crypter) Encrypt(input []byte) ([]byte, error) {
	ctx, err := openssl.NewEncryptionCipherCtx(c.cipher, nil, c.key, c.iv)
	if err != nil {
		return nil, err
	}

	cipherbytes, err := ctx.EncryptUpdate(input)
	if err != nil {
		return nil, err
	}

	finalbytes, err := ctx.EncryptFinal()
	if err != nil {
		return nil, err
	}

	cipherbytes = append(cipherbytes, finalbytes...)
	return cipherbytes, nil
}

// Use this example: https://play.golang.org/p/r3VObSIB4o
// return '(encrypted)Hash/Time' structure using received (Text/Pass) structure:
func encryptData(in EncryptRequest) (EncryptedResponse, error) {
	// var is a structure (with Hash and Time) to be returned
	encryptedResponse := EncryptedResponse{}

	// get key and iv (from createKeys func), using the Pass from received structure (EncryptRequest)
	key, iv := createKeys(in.Pass)

	// Initialize new crypter struct . Errors are ignored.
	crypter, _ := NewCrypter([]byte(key), []byte(iv))

	// Lets encode Text (from curl) using Encrypt method of Crypter structure (incl received Text).
	// And convert it to string. And make it a Hash in a response.
	encoded, _ := crypter.Encrypt([]byte(in.Text))                // returns serialized encoded text
	encodedToString := base64.StdEncoding.EncodeToString(encoded) // gives strings
	encryptedResponse.Hash = encodedToString
	// encryptedResponse.Time = time.Now() // added by Lev for debug

	return encryptedResponse, nil
}

func handlerEcnrypt(w http.ResponseWriter, r *http.Request) {

	encryptRequest := EncryptRequest{} // var with EncryptRequest structure (text/pass)

	// creates ^ structure from received JSON in curl - from Body of 'r'
	// actually creates encryptRequest.Text and encryptRequest.Pass from 'r':
	if err := json.NewDecoder(r.Body).Decode(&encryptRequest); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		// log.Println(encryptRequest, "2", r.Body) // delete me
		return
	}

	// sends the created var for encryption. As a result - returned the structure "EncryptedResponse" (hash/time),
	// which is filled
	encryptedResponse, err := encryptData(encryptRequest)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// forming the JSON HTTP Response (w)
	jsonEncrypt, err := json.Marshal(encryptedResponse)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Printing the JSON part of the HTTP response on the screen after the CURL
	fmt.Fprintf(w, "%s", jsonEncrypt)
}

// Decrypt - this is  METHOD for the structure 'Crypter'
func (c *Crypter) Decrypt(input []byte) ([]byte, error) {
	ctx, err := openssl.NewDecryptionCipherCtx(c.cipher, nil, c.key, c.iv)
	// log.Println("5--to decrypt: ", input, c.cipher, c.key, c.iv) // delete me
	if err != nil {
		return nil, err
	}

	cipherbytes, err := ctx.DecryptUpdate(input)
	// log.Println("6--cipherbytes: ", cipherbytes, err)
	if err != nil {
		return nil, err
	}

	finalbytes, err := ctx.DecryptFinal()
	// log.Println("7--finalbytes: ", finalbytes, err)
	if err != nil {
		return nil, err
	}

	cipherbytes = append(cipherbytes, finalbytes...)
	// log.Println("8--get to append cipherbytes", cipherbytes)
	return cipherbytes, nil
}

func decryptData(in DecryptRequest) (DecryptedResponse, error) {
	decryptedResponse := DecryptedResponse{} // var is a structure with Text and Time to response

	stringInBytes, _ := base64.StdEncoding.DecodeString(in.Hash)

	key, iv := createKeys(in.Pass)
	// fmt.Println("1b --- key: ", key, "iv: ", iv) // remove me

	// Initialize new crypter struct. Errors are ignored.
	crypter, _ := NewCrypter([]byte(key), []byte(iv))
	// fmt.Println("2--- crypter: ", crypter) // remove me

	// Decode. Should print same as what was received in 1st curl
	decoded, _ := crypter.Decrypt([]byte(stringInBytes))
	// fmt.Println("3--- decoded: ", decoded) // remove me

	// convert decoded bytes to (originl) string
	decodedBytesToString := string(decoded[:])

	// let's start preparing values for Response
	decryptedResponse.Text = decodedBytesToString

	return decryptedResponse, nil

}

func handlerDecrypt(w http.ResponseWriter, r *http.Request) {
	decryptRequest := DecryptRequest{} // variable with EncryptRequest structure (hmmm I could prepare better)

	// filling 'decryptRequest' structure from received JSON body in curl
	if err := json.NewDecoder(r.Body).Decode(&decryptRequest); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		log.Println(decryptRequest, "decrypt error", r.Body) // delete me
		return
	}

	// Convert received string to bytes:
	// stringInBytes, err := base64.StdEncoding.DecodeString(decryptRequest.Text)
	// if err != nil {
	// 	fmt.Println("error:", err)
	// 	return
	// }

	// sending the 'decryptRequest' to decryptData function
	decryptedResponse, err := decryptData(decryptRequest)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	jsonEncrypt, err := json.Marshal(decryptedResponse)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	fmt.Fprintf(w, "%s", jsonEncrypt)
}

// returning two strings by replacing first chars of hardcoded strings
// with the received 'pass' string
func createKeys(inPass string) (key, iv string) {

	// hardcoded, but better be imported from secret storage
	keyTemplate := "1234567890ABCDEF1234567890ABCDEF" // 32-bytes
	ivTemplate := "1234567890ABCDEF"                  // 16 bytes

	//Salt - TBD where to pass from or get from
	//salt := inSalt

	// password or passphrase
	pass := inPass

	return pass + keyTemplate[len(pass):], pass + ivTemplate[len(pass):]
}

func main() {

	http.HandleFunc("/api/v1/encrypt", handlerEcnrypt)

	http.HandleFunc("/api/v1/decrypt", handlerDecrypt)

	log.Fatal(http.ListenAndServe(":8081", nil))

}
