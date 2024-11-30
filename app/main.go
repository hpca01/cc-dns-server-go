package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

// Ensures gofmt doesn't remove the "net" import in stage 1 (feel free to remove this!)
var _ = net.ListenUDP

type DNSMessage struct {
	ID         uint16
	Flags      uint16
	QCount     uint16 // question count
	QDCount    int
	ACount     uint16 // answer count
	NSCount    uint16 // authority section
	ARCount    uint16 // additional section
	DomainName string // domain in question
	Rem        []byte //remaining buffer

}

type ResourceRecord struct {
	Name   string
	Type   uint16
	Class  uint16
	TTL    uint32
	Length uint16
	Data   uint32 // this is the IP address for IPV4 only
}

func (r *DNSMessage) ParseQuestion(data []byte) {
	// use & to get what it is currently set as, and then >> to get the 1st bit
	i := 0
	labels := []string{}
	for ; data[i] != 0; i++ {
		count := int(data[i])
		label := ""
		fmt.Printf("At idx: %d size of label: %d", i, count)
		fmt.Println()
		for j := i + 1; j <= i+count; j++ {
			label += string(int(data[j]))
		}
		labels = append(labels, label)
		i += count
	}
	// r.ACount = uint16(data[6])<<8 | uint16(data[7])    // same logic as before
	r.DomainName = strings.Join(labels, ".")
	fmt.Printf("Labels: [%s]", r.DomainName)
	fmt.Println()
}

func (r *DNSMessage) SetQueryResponse(response bool) {
	if response {
		//SET the 16thbit
		r.Flags |= 1 << 15
	} else {
		//UNSET the 16th bit
		r.Flags &^= 1 << 15
	}
}

func NewHeader() DNSMessage {
	return DNSMessage{}
}
func (r *DNSMessage) AnswerFrom() DNSMessage {
	resp := DNSMessage{}
	resp.ID = r.ID
	resp.SetQueryResponse(true)
	resp.DomainName = r.DomainName
	resp.QDCount = r.QDCount
	resp.ACount = 1
	resp.NSCount = 0
	resp.ARCount = 0

	return resp
}

func (r *DNSMessage) ToBytes() []byte {
	bytes := []byte{}
	bytes = binary.BigEndian.AppendUint16(bytes, r.ID)
	fmt.Printf("bytes: %d", bytes)
	fmt.Println()
	bytes = binary.BigEndian.AppendUint16(bytes, r.Flags)
	// question section
	bytes = binary.BigEndian.AppendUint16(bytes, uint16(r.QDCount))
	bytes = binary.BigEndian.AppendUint16(bytes, uint16(r.ACount))  // ANCOUNT
	bytes = binary.BigEndian.AppendUint16(bytes, uint16(r.NSCount)) // NSCOUNT
	bytes = binary.BigEndian.AppendUint16(bytes, uint16(r.ARCount)) // ARCOUNT
	bytes = append(bytes, EncodeDomain(r.DomainName)...)
	bytes = binary.BigEndian.AppendUint16(bytes, uint16(1)) // QTYPE
	bytes = binary.BigEndian.AppendUint16(bytes, uint16(1)) // QCLASS

	//answer section
	bytes = append(bytes, EncodeDomain(r.DomainName)...)
	bytes = binary.BigEndian.AppendUint16(bytes, uint16(1))  // TYPE
	bytes = binary.BigEndian.AppendUint16(bytes, uint16(1))  // CLASS
	bytes = binary.BigEndian.AppendUint32(bytes, uint32(60)) // TTL
	bytes = binary.BigEndian.AppendUint16(bytes, uint16(4))  // Length
	bytes = append(bytes, 0x08, 0x08, 0x08, 0x08)            // 8 8 8 8
	PrintBytesToHex(bytes)
	return bytes
}

func EncodeDomain(dName string) []byte {
	fmt.Printf("domain name [%s]\n", dName)
	encoding := []byte{}
	for _, segment := range strings.Split(dName, ".") {
		sizeOfSeg := len(segment)
		fmt.Printf("Segment [%s]\n", segment)
		encoding = append(encoding, byte(sizeOfSeg))
		encoding = append(encoding, []byte(segment)...)
	}
	encoding = append(encoding, 0x00)
	return encoding
}

func PrintBytesToHex(data []byte) {
	for _, b := range data {
		fmt.Printf(" %x ", b)
	}
}

func (r *DNSMessage) FromBytes(data []byte) error {
	if len(data) < 12 {
		return fmt.Errorf("header is too short")
	}
	r.ID = binary.BigEndian.Uint16(data[0:2])     // we're shifting the first byte 8 to left and then ORing it with the second set of 8 bytes cast to 16 bits.
	r.Flags = binary.BigEndian.Uint16(data[2:4])  // we're shifting the first byte 8 to left and then ORing it with the second set of 8 bytes cast to 16 bits.
	r.QCount = binary.BigEndian.Uint16(data[4:6]) // we're shifting the first byte 8 to left and then ORing it with the second set of 8 bytes cast to 16 bits.
	r.QDCount = int(r.QCount)
	fmt.Println("number of questions", r.QDCount)
	r.ACount = binary.BigEndian.Uint16(data[6:8])
	fmt.Println("number of ACount", r.ACount)
	r.NSCount = binary.BigEndian.Uint16(data[8:10])
	fmt.Println("number of NSCount", r.NSCount)
	r.ARCount = binary.BigEndian.Uint16(data[10:12])
	fmt.Println("number of ARCount", r.ARCount)
	r.ParseQuestion(data[12:])
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
		fmt.Printf("Received %d bytes from %s:[ %s ]\n", size, source, receivedData)
		//
		// Create an empty response
		header := NewHeader()
		if err := header.FromBytes(buf[:size]); err != nil {
			fmt.Println("Error parsing DNS ", err)
			continue
		}
		resp := header.AnswerFrom()

		_, err = udpConn.WriteToUDP(resp.ToBytes(), source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
