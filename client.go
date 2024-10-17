package main

import (
	"crypto/aes"
	"crypto/cipher"
	//"crypto/rsa"
	//"crypto/rand"
	//"crypto/sha256"
	"fmt"
	"net"
	"os"
	"log"
	"io"
	"strings"
)

func main() {
    if len(os.Args) != 3 {
        log.Fatalf("Usage: %s <server> <filename>:<depth>", os.Args[0])
    }

    server := os.Args[1]
    file := os.Args[2]
    origin := ":0:" // by default client's is set to 0 to indicate server will be origin
    file = file + origin

    // Génération de la paire de clés RSA
    privateKey, publicKey, err := GenerateRSAKeyPair(2048)
    if err != nil {
        log.Fatalf("Erreur lors de la génération des clés: %v", err)
    }

    // Encode la clé publique en Base64
    publicKeyBase64, err := EncodePublicKeyToBase64(publicKey)
    if err != nil {
        log.Fatalf("Erreur lors de l'encodage de la clé publique: %v", err)
    }
    file = file + publicKeyBase64

    // Connexion au serveur
    conn, err := net.Dial("tcp", server)
    if err != nil {
        fmt.Println("Error:", err)
        return
    }
    defer conn.Close()

    _, err = conn.Write([]byte(file))
    if err != nil {
        fmt.Println("Error sending filename:", err)
        return
    }

    // Lecture de la réponse du serveur
    buffer := make([]byte, 4096) // Increased buffer size to handle large data
    n, err := conn.Read(buffer)
    if err != nil && err != io.EOF {
        fmt.Println("Error reading from server:", err)
        return
    }
    response := string(buffer[:n])  // Convert buffer to string to check for "Error:"

    // Check if the response contains an error message
    if strings.Contains(response, "Error:") {
        fmt.Println("Server response:", response) // Print the error message and return
        return
    }

    // Convert the response back to bytes after checking for errors
    responseBytes := buffer[:n]

    // Split the response into the RSA-encrypted AES key and the AES-encrypted data
    rsaKeySize := privateKey.PublicKey.Size() // Get RSA key size (256 bytes for 2048-bit key)
    encryptedAESKey := responseBytes[:rsaKeySize]  // The first part is the RSA-encrypted AES key
    encryptedFileData := responseBytes[rsaKeySize:] // The rest is the AES-encrypted file data

    // Step 1: Decrypt the AES key using the RSA private key
    aesKey, err := DecryptWithPrivateKey(encryptedAESKey, privateKey)
    if err != nil {
        fmt.Println("Error decrypting AES key:", err)
        return
    }

    // Step 2: Decrypt the file data using the decrypted AES key
    decryptedFileData, err := DecryptWithAESKey(encryptedFileData, aesKey)
    if err != nil {
        fmt.Println("Error decrypting file data:", err)
        return
    }

    // Display the decrypted file content
    fmt.Println("Decrypted file content:", string(decryptedFileData))

}

// Decrypt AES-encrypted file data
func DecryptWithAESKey(cipherText []byte, aesKey []byte) ([]byte, error) {
    block, err := aes.NewCipher(aesKey)
    if err != nil {
        return nil, err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    nonceSize := gcm.NonceSize()
    if len(cipherText) < nonceSize {
        return nil, fmt.Errorf("ciphertext too short")
    }

    nonce, cipherText := cipherText[:nonceSize], cipherText[nonceSize:]
    return gcm.Open(nil, nonce, cipherText, nil) // Decrypt using AES-GCM
}
