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
	ques       Question
	ACount     uint16 // answer count
	NSCount    uint16 // authority section
	ARCount    uint16 // additional section
	DomainName string // domain in question
	Rem        []byte //remaining buffer

}
type Question struct {
	QName  []byte
	QType  uint16
	QClass uint16
}

func (r *DNSMessage) ParseQuestion() {
	// use & to get what it is currently set as, and then >> to get the 1st bit
	i := 0
	labels := []string{}
	for ; r.Rem[i] != 0; i++ {
		count := int(r.Rem[i])
		label := ""
		fmt.Printf("At idx: %d size of label: %d", i, count)
		fmt.Println()
		for j := i + 1; j <= i+count; j++ {
			label += string(int(r.Rem[j]))
		}
		labels = append(labels, label)
		i += count
	}
	ques := Question{}
	ques.QName = r.Rem[0 : i+1]
	ques.QType = uint16(r.Rem[i+1])<<8 | uint16(r.Rem[i+2])
	ques.QType = uint16(r.Rem[i+3])<<8 | uint16(r.Rem[i+3])
	r.ques = ques
	// r.ACount = uint16(data[6])<<8 | uint16(data[7])    // same logic as before
	r.DomainName = strings.Join(labels, ".")
	fmt.Printf("Labels: %s", r.DomainName)
	fmt.Println()
	PrintBytesToHex(r.Rem[i+1:])
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

func NewRespHeader() DNSMessage {
	return DNSMessage{}
}

func (r *DNSMessage) ToBytes() []byte {
	bytes := []byte{}
	bytes = append(bytes, byte(r.ID>>8))
	bytes = append(bytes, byte(r.ID))
	bytes = append(bytes, byte(r.Flags>>8))
	bytes = append(bytes, byte(r.Flags))
	bytes = append(bytes, 0b00000000)
	bytes = binary.BigEndian.AppendUint16(bytes, uint16(r.QDCount))
	bytes = binary.BigEndian.AppendUint16(bytes, r.ACount)
	bytes = binary.BigEndian.AppendUint16(bytes, r.NSCount)
	bytes = binary.BigEndian.AppendUint16(bytes, r.ARCount)
	bytes = append(bytes, EncodeDomain(r.DomainName)...)
	bytes = binary.BigEndian.AppendUint16(bytes, uint16(1))
	bytes = binary.BigEndian.AppendUint16(bytes, uint16(1))
	return bytes
}

func EncodeDomain(dName string) []byte {
	encoding := []byte{}
	for _, segment := range strings.Split(dName, ".") {
		sizeOfSeg := len(segment)
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
	r.ID = uint16(data[0])<<8 | uint16(data[1])     // we're shifting the first byte 8 to left and then ORing it with the second set of 8 bytes cast to 16 bits.
	r.Flags = uint16(data[2])<<8 | uint16(data[3])  // same logic as before
	r.QCount = uint16(data[4])<<8 | uint16(data[5]) // same logic as before
	r.QDCount = int(r.QCount)
	r.ACount = uint16(data[6])<<8 | uint16(data[7])    // same logic as before
	r.NSCount = uint16(data[8])<<8 | uint16(data[9])   // same logic as before
	r.ARCount = uint16(data[10])<<8 | uint16(data[11]) // same logic as before
	r.Rem = data[12:]
	fmt.Println("Question bytes")
	PrintBytesToHex(r.Rem)
	fmt.Println()
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
		header := NewRespHeader()
		if err := header.FromBytes(buf[:size]); err != nil {
			fmt.Println("Error parsing DNS ", err)
			continue
		}
		header.ParseQuestion()

		resp := NewRespHeader()
		resp.ID = header.ID
		resp.SetQueryResponse(true)

		_, err = udpConn.WriteToUDP(resp.ToBytes(), source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
