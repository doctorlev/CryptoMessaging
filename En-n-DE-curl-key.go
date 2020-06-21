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
	Salt string `json:"salt"`
}

// EncryptedResponse structure -  will be inserted into formed O/G Request after encryption
type EncryptedResponse struct {
	Hash string    `json:"hash"`
	Time time.Time `json:"time"`
}

// DecryptRequest structure - for encryption
type DecryptRequest struct {
	Hash string `json:"hash"`
	Salt string `json:"salt"`
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
func encryptData(in EncryptRequest) (EncryptedResponse, error) {

	encryptedResponse := EncryptedResponse{} // var is a structure with Hash and Salt

	// get key and iv, knowing the salt
	key, iv := createKeys(in.Salt)

	// Initialize new crypter struct. Errors are ignored.
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

	encryptRequest := EncryptRequest{} // variable with EncryptRequest structure

	// created structure from received JSON in curl
	if err := json.NewDecoder(r.Body).Decode(&encryptRequest); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		log.Println(encryptRequest, "2", r.Body) // delete me
		return
	}
	//
	encryptedResponse, err := encryptData(encryptRequest)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	jsonEncrypt, err := json.Marshal(encryptedResponse)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	fmt.Fprintf(w, "%s", jsonEncrypt) // this is returns the Response on the same screen as curl was inserted
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
	// fmt.Println("1a --- stringInBytes: ", stringInBytes, "\n", []byte(stringInBytes))
	// if err != nil {
	// 	fmt.Println("error:", err)
	// 	return (EncryptedResponse, err)
	// }

	// get key and iv
	// 1. hardcoded:
	// key := []byte("1234567890ABCDEF1234567890ABCDEF") // - to insert here the logic of putting salt to 32-byte key
	// iv := []byte("1234567890ABCDEF")                  // - can do the same for Salt
	// 2. from func 'create key, iv with salt':
	key, iv := createKeys(in.Salt)
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

func createKeys(inSalt string) (key, iv string) {

	// hardcoded, but better be imported from secret storage
	keyTemplate := "1234567890ABCDEF1234567890ABCDEF" // 32-bytes
	ivTemplate := "1234567890ABCDEF"                  // 16 bytes

	//Salt
	salt := inSalt

	//replace first bytes of key and iv with SALT
	x := len(salt)
	// modify templates to trim first (len) bytes
	// key := salt + keyTemplate[x:]
	// iv := salt + ivTemplate[x:]

	// fmt.Println(keyBytes111, "len(x): ", x, "\nkeyTemplate: ", keyTemplate, "\nivTemplate: ", ivTemplate, "\nkeyBytes: ", keyBytes, "\nivBytes: ", ivBytes)

	// fmt.Println("\nnewkey: ", key, "\nnew  iv: ", iv)

	return salt + keyTemplate[x:], salt + ivTemplate[x:]
}

func main() {

	http.HandleFunc("/api/v1/encrypt", handlerEcnrypt)

	http.HandleFunc("/api/v1/decrypt", handlerDecrypt)

	log.Fatal(http.ListenAndServe(":8081", nil))

}
