package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func decrypt(ciphertext []byte, key []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    if len(ciphertext) < aes.BlockSize {
        return nil, fmt.Errorf("ciphertext too short")
    }

    iv := ciphertext[:aes.BlockSize]
    ciphertext = ciphertext[aes.BlockSize:]

    stream := cipher.NewCFBDecrypter(block, iv)
    stream.XORKeyStream(ciphertext, ciphertext)

    return ciphertext, nil
}


func decryptAndDisplayFile(encryptedData []byte, key []byte) (string, error) {
    decryptedData, err := decrypt(encryptedData, key)
    if err != nil {
        return "", fmt.Errorf("error decrypting file: %v", err)
    }
    return string(decryptedData), nil
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

func generateEncryptedFile(fileName string, address string, key []byte) ([]byte, error) {
	fileContent := fmt.Sprintf("File from: %s, file content: %s", address, fileName)
	encryptedData, err := encrypt([]byte(fileContent), key)
	if err != nil {
		return nil, fmt.Errorf("error encrypting file: %v", err)
	}
	return encryptedData, nil
}

func loadServer(fileName string) [][]string {
	filePath := filepath.Join("./servers_cipher", fileName)
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

		serverInfo = append(serverInfo, []string{letterRange, serverAddress})
	}

	return serverInfo
}

func loadLetters(fileName string) string {
	filePath := filepath.Join("./files_ciphers", fileName)
	content, err := os.ReadFile(filePath)
	if err != nil {
		log.Printf("Error reading file %s: %v", filePath, err)
		return ""
	}
	fmt.Println("These are the letters allowed", string(content))
	return string(content)
}

func main() {
	if len(os.Args) != 4 {
		log.Fatalf("Usage: %s <port> <file_list_file> <server_file>", os.Args[0])
	}

	port := os.Args[1]
	files := loadLetters(os.Args[2])
	childServer := loadServer(os.Args[3])

	// Clé symétrique AES-256 CFB
	key := []byte("9HLR1qTRtQWSgSMBO6dW7IdjSL7lCwDIeJkRDwpJreA=")

	l, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	fmt.Printf("Listening on port %s...\n", port)

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go func(c net.Conn) {
			fmt.Println("New connection received")

			buffer := make([]byte, 1024)

			n, err := c.Read(buffer)
			if err != nil {
				if err != io.EOF {
					log.Println("Error reading from connection:", err)
				}
				c.Close()
				return
			}

			receivedData := string(buffer[:n])

			parts := strings.Split(receivedData, ":")
			if len(parts) != 2 {
				c.Write([]byte("Invalid input format, expected nomdufichier.extension:depth"))
				return
			}

			fileName := parts[0]
			depthStr := strings.TrimSpace(parts[1])

			depth, err := strconv.Atoi(depthStr)
			if err != nil {
				c.Write([]byte("Invalid depth value"))
				return
			}

			fmt.Println("Depth received", depth)
			if depth > 0 {
				if strings.Contains(files, string(fileName[0])) {
					encryptedData, err := generateEncryptedFile(fileName, port, key)
					if err != nil {
						c.Write([]byte(fmt.Sprintf("Error generating encrypted file: %v", err)))
						return
					}
					c.Write(encryptedData)
				} else {
					fmt.Println("Next server is", childServer)
					conn, err := net.Dial("tcp", childServer[0][1])  
					if err != nil {
						fmt.Println("Error:", err)
						return
					}
					defer conn.Close()

					newDepth := depth - 1
					fileToSend := fmt.Sprintf("%s:%d", fileName, newDepth)
					_, err = conn.Write([]byte(fileToSend))
					if err != nil {
						fmt.Println("Error sending filename:", err)
						return
					}

					returnString := ""
					buffer := make([]byte, 1024)
					for {
						n, err := conn.Read(buffer)
						if err == io.EOF {
							break
						} else if err != nil {
							fmt.Println("Error reading from server:", err)
							return
						}
						returnString += string(buffer[:n])
					}
					c.Write([]byte(returnString))
				}
			} else {
				c.Write([]byte("Depth exceeded"))
			}
			c.Close()
		}(conn)
	}
}
