# How to use the raft demo

* Open multiple terminals, to match the numbers of server ports written in servers.lst
* In each terminal, run the following command with the appropriate port number: `go run utils.go server.go 1250 servers.lst`
* To run a client, use the command: `go run utils.go client.go a.txt`

If the error: `./server.go:314:18: other declaration of handleDel` happens, remove the lines *332*, *333*, *334* from `server.go`
