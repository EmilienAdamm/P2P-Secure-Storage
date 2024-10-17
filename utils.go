package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"	
	"crypto/sha256"
	"crypto/rand"
	"crypto/x509"
    //"encoding/pem"
	"fmt"
	"io"
	"os"
	"strings"
	"path/filepath"
	"log"
	"encoding/base64"
	//"strconv"
)

func EncryptFileWithAES(data []byte) ([]byte, []byte, error) {
    aesKey := make([]byte, 32) // 256-bit AES key
    _, err := rand.Read(aesKey)
    if err != nil {
        return nil, nil, fmt.Errorf("Error generating AES key: %v", err)
    }

    block, err := aes.NewCipher(aesKey)
    if err != nil {
        return nil, nil, fmt.Errorf("Error creating AES cipher: %v", err)
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, nil, fmt.Errorf("Error creating GCM: %v", err)
    }

    nonce := make([]byte, gcm.NonceSize())
    _, err = io.ReadFull(rand.Reader, nonce)
    if err != nil {
        return nil, nil, fmt.Errorf("Error generating nonce: %v", err)
    }

    ciphertext := gcm.Seal(nonce, nonce, data, nil)
    return ciphertext, aesKey, nil
}

func EncryptAESKeyWithRSA(aesKey []byte, rsaPublicKey *rsa.PublicKey) ([]byte, error) {
    encryptedAESKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPublicKey, aesKey, nil)
    if err != nil {
        return nil, fmt.Errorf("Error encrypting AES key: %v", err)
    }
    return encryptedAESKey, nil
}


func EncodePublicKeyToBase64(pub *rsa.PublicKey) (string, error) {
	// Convert the RSA public key to a DER-encoded PKIX structure
	pubASN1, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}

	// Encode the public key to Base64
	pubBase64 := base64.StdEncoding.EncodeToString(pubASN1)
	return pubBase64, nil
}

func GenerateRSAKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
    privateKey, err := rsa.GenerateKey(rand.Reader, bits)
    if err != nil {
        return nil, nil, err
    }
    publicKey := &privateKey.PublicKey
    return privateKey, publicKey, nil
}

func DecryptWithPrivateKey(cipherText []byte, priv *rsa.PrivateKey) ([]byte, error) {
    // Use SHA-256 as hash function and OAEP padding scheme for decryption
    plainText, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, cipherText, nil)
    if err != nil {
        return nil, err
    }
    return plainText, nil
}

// EncryptWithPublicKey encrypts data using the provided public key
func EncryptWithPublicKey(msg []byte, pub *rsa.PublicKey) ([]byte, error) {
    // Use SHA-256 as hash function and OAEP padding scheme for encryption
    cipherText, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, msg, nil)
    if err != nil {
        return nil, err
    }
    return cipherText, nil
}

func encrypt(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv) // On utilise CFB 
	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)

	return ciphertext, nil
}

/*
	Returns the list of files and address of servers known.
	Format of return : [ [file_letters address] ]
*/
func loadServer(fileName string) [][]string {
	filePath := filepath.Join("./servers", fileName)
	content, err := os.ReadFile(filePath)
	if err != nil {
		log.Printf("Error reading file %s: %v", filePath, err)
		return nil
	}

	lines := strings.Split(string(content), "\n")
	var serverInfo [][]string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) != 2 {
			log.Printf("Invalid format in line: %s", line)
			continue
		}

		letterRange := parts[0]
		serverAddress := parts[1]

		letterBounds := strings.Split(letterRange, "-")
		if len(letterBounds) != 2 {
			log.Printf("Invalid letter range format: %s", letterRange)
			continue
		}

		startLetter := rune(letterBounds[0][0])
		endLetter := rune(letterBounds[1][0])

		var letters []string
		for ch := startLetter; ch <= endLetter; ch++ {
			letters = append(letters, string(ch))
		}

		serverInfo = append(serverInfo, []string{strings.Join(letters, ""), serverAddress})
	}

	return serverInfo
}

/*
	Returns the files the server deals with
*/
func loadLetters(fileName string) string {
	filePath := filepath.Join("./files", fileName)
	content, err := os.ReadFile(filePath)
	if err != nil {
		log.Printf("Error reading file %s: %v", filePath, err)
		return ""
	}
	fmt.Println("These are the letters allowed", string(content))
	return string(content)
}

/*
	Function to simulate fake file data. Returns what server had the file to better understand results.
*/
func generateFakeFile(fileName string, address string) string {
	returnString := fmt.Sprintf("File from: %s, file content: %s", address, fileName)
	return returnString
}
