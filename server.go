package main

import (
	//"crypto/rand"
	"crypto/rsa"
	//"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
)

func main() {
	if len(os.Args) != 4 {
		log.Fatalf("Usage: %s <port> <file_list_file> <server_file>", os.Args[0])
	}

	port := os.Args[1]
	files := loadLetters(os.Args[2])
	servers := loadServer(os.Args[3])

	l, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	fmt.Printf("Listening on port %s...\n", port)

	for { // Deal with incoming connections
		conn, err := l.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go func(c net.Conn) {
			fmt.Println("-----------------------")
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
			if len(parts) != 4 {
				c.Write([]byte("Invalid input format, expected nomdufichier.extension:depth:origine:pubkey"))
				return
			}

			fileName 	:= 	parts[0]
			depthStr 	:= 	strings.TrimSpace(parts[1])
			origin		:=	parts[2]
			publicKey	:=	parts[3]

			fmt.Println("FILE NAME IS ", fileName)
			if origin == "0" {
				origin = port
			}

			if (fileName == "all") {
				c.Write([]byte("My files are " + files))
				return
			}

			depth, err := strconv.Atoi(depthStr)
			if err != nil {
				c.Write([]byte("Invalid depth value"))
				return
			}

			fmt.Println("Depth received", depth)
			if depth > 0 {
				if strings.Contains(files, string(fileName[0])) {
					var err error
				
					// Decode the public key from base64
					publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKey)
					if err != nil {
						c.Write([]byte(fmt.Sprintf("Error decoding public key: %v", err)))
						return
					}
				
					// Convert the decoded bytes into a usable RSA public key
					publicKeyInterface, err := x509.ParsePKIXPublicKey(publicKeyBytes)
					if err != nil {
						c.Write([]byte(fmt.Sprintf("Error parsing public key: %v", err)))
						return
					}
				
					rsaPublicKey, ok := publicKeyInterface.(*rsa.PublicKey)
					if !ok {
						c.Write([]byte("Error: public key is not of type RSA"))
						return
					}
				
					// Generate fake file data
					fakeFileData := generateFakeFile(fileName, ""+port)
				
					// Encrypt the file data using AES
					encryptedFileData, aesKey, err := EncryptFileWithAES([]byte(fakeFileData))
					if err != nil {
						c.Write([]byte(fmt.Sprintf("Error encrypting file with AES: %v", err)))
						return
					}
				
					// Encrypt the AES key using RSA
					encryptedAESKey, err := EncryptAESKeyWithRSA(aesKey, rsaPublicKey)
					if err != nil {
						c.Write([]byte(fmt.Sprintf("Error encrypting AES key: %v", err)))
						return
					}
				
					// Send both the encrypted AES key and encrypted file data
					c.Write(append(encryptedAESKey, encryptedFileData...))
				} else {
					var mainServer, backupServer string
					if strings.Contains(servers[0][0], string(fileName[0])) { // Determine next and backup server to transmit the request to
						mainServer, backupServer = servers[0][1], servers[1][1]
					} else {
						mainServer, backupServer = servers[1][1], servers[0][1]
					}

					if strings.Contains(mainServer, origin) {
						c.Write([]byte("Error: loop detected, file could not be served."))
					} else {
						conn, err := net.Dial("tcp", mainServer)
						if err != nil { // Connectivity error, connecting to backup server, unless loop
							if strings.Contains(backupServer, origin) {
								c.Write([]byte("Error: loop detected, file could not be served."))
							} else {
								fmt.Println("Error while connecting to server, using backup server")
								conn, err = net.Dial("tcp", backupServer)
								if err != nil {
									fmt.Println("Error while connecting to back up server")
									return
								}
							}
						}
						defer conn.Close()

						newDepth := depth - 1
						fileToSend := fmt.Sprintf("%s:%d:%s:%s", fileName, newDepth, port, publicKey)
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
							fmt.Println("File I am transmitting is", returnString)
						}
						c.Write([]byte(returnString))
					}
				}
			} else {
				c.Write([]byte("Depth exceeded"))
			}
			c.Close()
		}(conn)
	}
}
