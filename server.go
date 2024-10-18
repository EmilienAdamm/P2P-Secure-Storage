package main

import (
	"bufio"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	follower  = "FOLLOWER"
	candidate = "CANDIDATE"
	leader    = "LEADER"
)

type Server struct {
	port              string
	status            string
	electionTimeout   time.Duration
	heartbeatInterval time.Duration
	mu                sync.Mutex
	resetTimerCh      chan struct{}
	otherPorts        []string
	votesReceived     int
	totalServers      int
}

func NewServer(port string, portsFile string) (*Server, error) {
	otherPorts, err := readPortsFile(portsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read ports file: %v", err)
	}

	// Remove own port from otherPorts if present
	for i, p := range otherPorts {
		if p == port {
			otherPorts = append(otherPorts[:i], otherPorts[i+1:]...)
			break
		}
	}

	return &Server{
		port:              port,
		status:            follower,
		electionTimeout:   time.Duration(5+rand.Intn(4)) * time.Second,
		heartbeatInterval: 2 * time.Second,
		resetTimerCh:      make(chan struct{}),
		otherPorts:        otherPorts,
		totalServers:      len(otherPorts) + 1, // including self
	}, nil
}

func readPortsFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var ports []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ports = append(ports, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return ports, nil
}

func (s *Server) Start() error {
	l, err := net.Listen("tcp", ":"+s.port)
	if err != nil {
		return fmt.Errorf("failed to listen on port %s: %v", s.port, err)
	}
	defer l.Close()

	fmt.Printf("Listening on port %s...\n", s.port)
	fmt.Printf("Election timeout set to %v\n", s.electionTimeout)

	go s.runElectionTimer()

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			continue
		}
		go s.handleConnection(conn)
	}
}

func (s *Server) runElectionTimer() {
	for {
		select {
		case <-time.After(s.electionTimeout):
			s.mu.Lock()
			if s.status == follower {
				s.status = candidate
				s.votesReceived = 1 // Start with 1 vote (self-vote)
				fmt.Println("Timeout reached. Server status changed to:", s.status)
				fmt.Println("Starting with 1 vote (self)")
				go s.startElection()
			}
			s.mu.Unlock()
		case <-s.resetTimerCh:
			fmt.Println("Timer reset due to heartbeat")
		}
	}
}

func (s *Server) startElection() {
	fmt.Println("Starting election")
	for _, port := range s.otherPorts {
		go s.sendVoteRequest(port)
	}
}

func (s *Server) sendVoteRequest(port string) {
	conn, err := net.Dial("tcp", "localhost:"+port)
	if err != nil {
		log.Printf("Error connecting to %s: %v", port, err)
		return
	}
	defer conn.Close()

	_, err = fmt.Fprintf(conn, "VOTE\n")
	if err != nil {
		log.Printf("Error sending VOTE message to %s: %v", port, err)
		return
	}

	response, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		log.Printf("Error reading response from %s: %v", port, err)
		return
	}

	response = strings.TrimSpace(response)
	fmt.Printf("Received vote response from %s: %s\n", port, response)

	if response == "YES" {
		s.mu.Lock()
		s.votesReceived++
		if s.status == candidate && s.votesReceived > s.totalServers/2 {
			s.status = leader
			fmt.Printf("Received majority of votes (%d/%d). Becoming LEADER\n", s.votesReceived, s.totalServers)
			go s.sendHeartbeats()
		}
		s.mu.Unlock()
	}
}

func (s *Server) sendHeartbeats() {
	for {
		s.mu.Lock()
		if s.status != leader {
			s.mu.Unlock()
			return
		}
		s.mu.Unlock()

		for _, port := range s.otherPorts {
			go s.sendHeartbeat(port)
		}
		go s.sendHeartbeat("1260") // include client in case it exists to inform it of the leader
		time.Sleep(s.heartbeatInterval)
	}
}

func (s *Server) sendHeartbeat(port string) {
	if port == "1260" {
		conn, err := net.Dial("tcp", "localhost:"+port)
		if err != nil {
			log.Printf("Error connecting to %s: %v", port, err)
			return
		}
		defer conn.Close()
	
		heartbeatMsg := fmt.Sprintf("HEARTBEAT %s\n", s.port)
		_, err = fmt.Fprintf(conn, heartbeatMsg)
		if err != nil {
			log.Printf("Error sending HEARTBEAT message to %s: %v", port, err)
		}
	} else {
		conn, err := net.Dial("tcp", "localhost:"+port)
		if err != nil {
			log.Printf("Error connecting to %s: %v", port, err)
			return
		}
		defer conn.Close()
	
		_, err = fmt.Fprintf(conn, "HEARTBEAT\n")
		if err != nil {
			log.Printf("Error sending HEARTBEAT message to %s: %v", port, err)
		}
	}
}

func (s *Server) handleConnection(conn net.Conn) {
    defer conn.Close()
    conn.SetReadDeadline(time.Now().Add(5 * time.Second))

    reader := bufio.NewReader(conn)
    message, err := reader.ReadString('\n')
    if err != nil {
        log.Printf("Error reading from connection: %v", err)
        return
    }

    message = strings.TrimSpace(message)
    fmt.Printf("Received message: %s\n", message)

    // Split the message into command and arguments
    fields := strings.Fields(message)
    if len(fields) == 0 {
        log.Printf("Empty message received")
        return
    }
    command := fields[0]
    args := fields[1:] // Slice of arguments

    switch command {
    case "HEARTBEAT":
        s.handleHeartbeat()
    case "VOTE":
        s.handleVote(conn)
    case "GET":
        s.handleGet(args, conn)
    case "ADD":
        s.handleAdd(args, conn)
    case "DEL":
        s.handleDel(args, conn)
    default:
        log.Printf("Unknown command: %s", command)
    }
}


func (s *Server) handleHeartbeat() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.status != leader {
		s.status = follower
		fmt.Println("Received HEARTBEAT, resetting to FOLLOWER")
		s.resetTimerCh <- struct{}{}
	}
}

func (s *Server) handleVote(conn net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	var response string
	if s.status == follower {
		response = "YES"
		s.resetTimerCh <- struct{}{} // Reset election timer
	} else {
		response = "NO"
	}
	
	_, err := fmt.Fprintf(conn, "%s\n", response)
	if err != nil {
		log.Printf("Error sending vote response: %v", err)
	}
	fmt.Printf("Sent vote response: %s\n", response)
}

func (s *Server) handleAdd(args []string, conn net.Conn) {
    if len(args) != 1 {
        log.Printf("ADD command requires exactly one argument")
        _, _ = fmt.Fprintf(conn, "ERROR Invalid number of arguments for ADD\n")
        return
    }
    filename := args[0]
    fmt.Printf("Handling ADD for file: %s\n", filename)

    // Simulate adding the file
    // Here you would implement the logic to add the file to your system
    // For demonstration, we'll just send a success response

    _, err := fmt.Fprintf(conn, "OK File %s added successfully\n", filename)
    if err != nil {
        log.Printf("Error sending response: %v", err)
    }
}


func (s *Server) handleGet(args []string, conn net.Conn) {
    if len(args) != 1 {
        log.Printf("GET command requires exactly one argument")
        _, _ = fmt.Fprintf(conn, "ERROR Invalid number of arguments for GET\n")
        return
    }
    filename := args[0]
    fmt.Printf("Handling GET for file: %s\n", filename)

    // Implement logic to retrieve the file
    // For demonstration, we'll simulate success

    _, err := fmt.Fprintf(conn, "OK File %s retrieved successfully\n", filename)
    if err != nil {
        log.Printf("Error sending response: %v", err)
    }
}

func (s *Server) handleDel(args []string, conn net.Conn) {
    if len(args) != 1 {
        log.Printf("DEL command requires exactly one argument")
        _, _ = fmt.Fprintf(conn, "ERROR Invalid number of arguments for DEL\n")
        return
    }
    filename := args[0]
    fmt.Printf("Handling DEL for file: %s\n", filename)

    // Implement logic to delete the file
    // For demonstration, we'll simulate success

    _, err := fmt.Fprintf(conn, "OK File %s deleted successfully\n", filename)
    if err != nil {
        log.Printf("Error sending response: %v", err)
    }
}

func (s *Server) handleGet()     { fmt.Println("Handling GET") }
func (s *Server) handleAdd()     { fmt.Println("Handling ADD") }
func (s *Server) handleDel()     { fmt.Println("Handling DEL") }

func main() {
	if len(os.Args) != 3 {
		log.Fatalf("Usage: %s <port> <ports_file>", os.Args[0])
	}

	port := os.Args[1]
	portsFile := os.Args[2]

	rand.Seed(time.Now().UnixNano())

	server, err := NewServer(port, portsFile)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	if err := server.Start(); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}