package main

import (
	"fmt"
	"net"
)

// Ensures gofmt doesn't remove the "net" import in stage 1 (feel free to remove this!)
var _ = net.ListenUDP

type RespHeader struct {
	ID    uint16
	Flags uint16
}

func NewRespHeader() RespHeader {
	return RespHeader{}
}

func (r *RespHeader) ToBytes() []byte {
	bytes := make([]byte, 12)
	bytes[0] = byte(r.ID >> 8) //shift 8 bits to right, we only use the last 8 bits
	bytes[1] = byte(r.ID)      //we only use the last 8 bits, so this is the second half of the 16 bits
	bytes[2] = byte(r.Flags >> 8)
	bytes[3] = byte(r.Flags)
	return bytes
}

func (r *RespHeader) FromBytes(data []byte) error {
	if len(data) < 12 {
		return fmt.Errorf("header is too short")
	}
	r.ID = uint16(data[0])<<8 | uint16(data[1])    // we're shifting the first byte 8 to left and then ORing it with the second set of 8 bytes cast to 16 bits.
	r.Flags = uint16(data[2])<<8 | uint16(data[3]) // same logic as before
	return nil
}

func main() {
	// You can use print statements as follows for debugging, they'll be visible when running tests.
	fmt.Println("Logs from your program will appear here!")

	// Uncomment this block to pass the first stage
	//
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:2053")
	if err != nil {
		fmt.Println("Failed to resolve UDP address:", err)
		return
	}
	//
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println("Failed to bind to address:", err)
		return
	}
	defer udpConn.Close()
	//
	buf := make([]byte, 512)
	//
	for {
		size, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			break
		}
		//
		receivedData := string(buf[:size])
		fmt.Printf("Received %d bytes from %s: %s\n", size, source, receivedData)
		//
		// Create an empty response
		header := NewRespHeader()
		if err := header.FromBytes(buf[:size]); err != nil {
			fmt.Println("Error parsing DNS ", err)
			continue
		}

		resp := NewRespHeader()
		resp.ID = header.ID
		resp.Flags |= (1 << 15)

		_, err = udpConn.WriteToUDP(resp.ToBytes(), source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
