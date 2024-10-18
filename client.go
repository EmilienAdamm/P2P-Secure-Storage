package main

import (
    "bufio"
    "fmt"
    "log"
    "net"
    "os"
    "strings"
    "sync"
)

const clientPort = "1260"

type Client struct {
    leaderAddr  string
    mu          sync.Mutex
    filename    string
    operation   string
    requestSent int // Indicates if the request has been sent
}

func NewClient(filename string) *Client {
    return &Client{
        filename:    filename,
        operation:   "ADD", // Default operation
        requestSent: 0, // Initialize as not sent
    }
}

func (c *Client) Start() error {
    listener, err := net.Listen("tcp", ":"+clientPort)
    if err != nil {
        return fmt.Errorf("failed to start client listener: %v", err)
    }
    defer listener.Close()

    fmt.Printf("Client listening on port %s...\n", clientPort)
    fmt.Printf("Waiting for leader heartbeat...\n")

    for {
        conn, err := listener.Accept()
        if err != nil {
            log.Printf("Error accepting connection: %v", err)
            continue
        }
        go c.handleConnection(conn)
    }
}

func (c *Client) handleConnection(conn net.Conn) {
    if c.requestSent == 1 {
        conn.Close()
        return
    } else {
        defer conn.Close()
    }

    fmt.Println("Incoming connection")
    message, err := bufio.NewReader(conn).ReadString('\n')
    if err != nil {
        log.Printf("Error reading message: %v", err)
        return
    }

    message = strings.TrimSpace(message)
    if strings.HasPrefix(message, "HEARTBEAT") {
        parts := strings.Split(message, " ")
        if len(parts) != 2 {
            log.Printf("Invalid HEARTBEAT message: %s", message)
            return
        }
        leaderPort := parts[1]

        c.mu.Lock()
        //newLeaderAddr := "localhost:" + leaderPort
        c.leaderAddr = leaderPort
        // If the request hasn't been sent, send it
        if c.requestSent == 0 {
            c.mu.Unlock()
            fmt.Printf("Received heartbeat from leader: %s\n", c.leaderAddr)
            go c.sendRequest()
        } else {
            c.mu.Unlock()
            fmt.Printf("Received heartbeat from leader: %s, but request already sent\n", c.leaderAddr)
        }
    }
}

func (c *Client) sendRequest() {
    c.mu.Lock()
    leaderAddr := c.leaderAddr
    c.mu.Unlock()

    if leaderAddr == "" {
        log.Println("No leader address available")
        return
    }

    conn, err := net.Dial("tcp", "localhost:"+leaderAddr)
    if err != nil {
        log.Printf("Error connecting to leader: %v", err)
        c.mu.Lock()
        c.requestSent = 0 // Reset requestSent to retry later
        c.mu.Unlock()
        return
    }
    defer conn.Close()

    request := fmt.Sprintf("%s %s\n", c.operation, c.filename)
    _, err = fmt.Fprint(conn, request)
    if err != nil {
        log.Printf("Error sending request to leader: %v", err)
        c.mu.Lock()
        c.requestSent = 0 // Reset requestSent to retry later
        c.mu.Unlock()
        return
    }

    fmt.Printf("Sent request to leader: %s", request)

    response, err := bufio.NewReader(conn).ReadString('\n')
    if err != nil {
        log.Printf("Error reading response from leader: %v", err)
        c.mu.Lock()
        c.requestSent = 1 // Reset requestSent to retry later
        c.mu.Unlock()
        return
    }

    fmt.Printf("Received response from leader: %s", response)

    c.handleResponse(response)
}

func (c *Client) handleResponse(response string) {
    parts := strings.SplitN(response, " ", 2)
    if len(parts) != 2 {
        log.Printf("Invalid response format: %s", response)
        return
    }

    status := parts[0]
    content := strings.TrimSpace(parts[1])
    c.requestSent = 2
    switch status {
    case "OK":
        fmt.Printf("Operation %s on file %s successful. Server response: %s\n", c.operation, c.filename, content)
    case "ERROR":
        fmt.Printf("Error from server: %s\n", content)
    default:
        log.Printf("Unknown response status: %s", status)
    }

}

func main() {
    if len(os.Args) != 2 {
        log.Fatalf("Usage: %s <filename>", os.Args[0])
    }

    filename := os.Args[1]
    client := NewClient(filename)

    if err := client.Start(); err != nil {
        log.Fatalf("Client failed to start: %v", err)
    }
}
