package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

// Ensures gofmt doesn't remove the "net" import in stage 1 (feel free to remove this!)
var _ = net.ListenUDP

type DNSmessage struct {
	ID        uint16
	Flags     HeaderFlags
	QCount    uint16 // question count
	QDCount   int
	ACount    uint16 // answer count
	NSCount   uint16 // authority section
	ARCount   uint16 // additional section
	Questions []Question
}

type Question struct {
	QName  string
	QType  uint16
	QClass uint16
}

type RawHeader []byte
type RawHeaderFlags []byte

/*
*
  - Parse the DNS header
  - QR: Query/ Response Indicator (1 bit)
  - Opcode: Operation Code (4 bits)
  - AA: Authoritative Answer (1 bit)
  - TC: Truncation Flag (1 bit)
  - RD: Recursion Desired (1 bit)
  - RA: Recursion Available (1 bit)
  - Z: Reserved for future use (3 bits) Used by DNSSEC queries. At inception, it was reserved for future use.
  - RCODE: Response Code (4 bits)
*/

type HeaderFlags struct {
	QR     uint16
	OPCODE uint16
	AA     uint16
	TC     uint16
	RD     uint16
	RA     uint16
	Z      uint16
	RCODE  uint16
}

func (rawH RawHeaderFlags) parse() HeaderFlags {
	flags := binary.BigEndian.Uint16(rawH)
	opcode := (flags >> 11) & 0b00001111
	rcode := flags & 0b00001111
	if opcode != 0 {
		rcode = 4
	}
	header := HeaderFlags{
		QR:     (0b0000000000000001),
		OPCODE: opcode,
		AA:     (flags >> 10) & 0x1,
		TC:     (flags >> 9) & 0x1,
		RD:     (flags >> 8) & 0x1,
		RA:     (flags >> 7) & 0x1,
		Z:      (flags >> 4) & 0x07,
		RCODE:  rcode,
	}
	return header
}

func (h HeaderFlags) toUint16() uint16 {
	flags := h.QR<<15 | h.OPCODE<<11 | h.AA<<10 | h.TC<<9 | h.RD<<8 |
		h.RA<<7 | h.Z<<4 | h.RCODE
	return flags
}

func parseLabel(data []byte, allData []byte) string {
	idx := 0
	labels := []string{}
	for {
		if data[idx] == 0 {
			break
		}
		// when a pointer is there it is padded with two bits 11 - 11000000
		if (data[idx]&0b11000000)>>6 == 0b11 {
			// pointer is everything after the two bits 11
			ptr := binary.BigEndian.Uint16(data[idx : idx+2])
			ptr <<= ptr              // move left 2 to get rid of the 11 padding
			ptr >>= ptr              // move right 2 to return back to the original value
			ptrConverted := int(ptr) // convert back to int
			length := bytes.Index(allData[ptrConverted:], []byte{0})
			labels = append(labels, parseLabel(allData[ptrConverted:ptrConverted+length+1], allData))
			idx += 2
			continue
		}
		len := int(data[idx])
		subStr := data[idx+1 : idx+1+len]
		labels = append(labels, string(subStr))
		idx += len + 1
	}
	return strings.Join(labels, ".")
}

func (r *DNSmessage) ParseQuestion(data []byte, qcount int, offset int) {
	var i = offset
	fmt.Printf("Question Bytes %+v\n", data)
	labels := []string{}
	for ; qcount > 0; qcount-- {
		nextNullSegment := bytes.Index(data[i:], []byte{0})
		labels = append(labels, parseLabel(data[i:i+nextNullSegment+1], data))
		i += 4
	}
	for _, label := range labels {
		r.Questions = append(r.Questions, Question{label, uint16(1), uint16(1)})
	}
}

func NewHeader() DNSmessage {
	return DNSmessage{}
}

func (r *DNSmessage) AnswerFrom() DNSmessage {
	resp := DNSmessage{}
	resp.ID = r.ID
	resp.Flags = r.Flags
	resp.QDCount = r.QDCount
	resp.ACount = r.ACount
	resp.NSCount = r.NSCount
	resp.ARCount = r.ARCount
	resp.Questions = r.Questions
	return resp
}

func (r *DNSmessage) ToBytes() []byte {
	bytes := []byte{}
	bytes = binary.BigEndian.AppendUint16(bytes, r.ID)
	bytes = binary.BigEndian.AppendUint16(bytes, r.Flags.toUint16())
	// question section
	bytes = binary.BigEndian.AppendUint16(bytes, uint16(r.QDCount))
	bytes = binary.BigEndian.AppendUint16(bytes, uint16(r.QDCount)) // ANCOUNT == same as QDCOUNT
	bytes = binary.BigEndian.AppendUint16(bytes, uint16(r.NSCount)) // NSCOUNT
	bytes = binary.BigEndian.AppendUint16(bytes, uint16(r.ARCount)) // ARCOUNT
	fmt.Printf("%+v\n", r.Questions)
	for _, question := range r.Questions {
		fmt.Printf("Question: %+v\n", question)
		bytes = append(bytes, EncodeDomain(question.QName)...)
		bytes = binary.BigEndian.AppendUint16(bytes, uint16(1)) // QTYPE
		bytes = binary.BigEndian.AppendUint16(bytes, uint16(1)) // QCLASS
	}

	for _, question := range r.Questions {
		//answer section
		bytes = append(bytes, EncodeDomain(question.QName)...)
		bytes = binary.BigEndian.AppendUint16(bytes, uint16(1)) // TYPE
		bytes = binary.BigEndian.AppendUint16(bytes, uint16(1)) // CLASS
		bytes = binary.BigEndian.AppendUint32(bytes, uint32(0)) // TTL
		bytes = binary.BigEndian.AppendUint16(bytes, uint16(4)) // Length
		bytes = append(bytes, 0x08, 0x08, 0x08, 0x08)           // 8 8 8 8
	}

	fmt.Printf("Output bytes: %+v\n", bytes)
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

func PrintBytesToInt(data []byte) {
	for _, b := range data {
		fmt.Printf(" %d ", b)
	}
}

func (r *DNSmessage) FromBytes(data []byte) error {
	if len(data) < 12 {
		return fmt.Errorf("header is too short")
	}
	r.ID = binary.BigEndian.Uint16(data[0:2])     // we're shifting the first byte 8 to left and then ORing it with the second set of 8 bytes cast to 16 bits.
	r.Flags = RawHeaderFlags(data[2:4]).parse()   // we're shifting the first byte 8 to left and then ORing it with the second set of 8 bytes cast to 16 bits..
	r.QCount = binary.BigEndian.Uint16(data[4:6]) // we're shifting the first byte 8 to left and then ORing it with the second set of 8 bytes cast to 16 bits.
	r.QDCount = int(r.QCount)
	fmt.Printf("QD count received %d \n", r.QDCount)
	r.ACount = binary.BigEndian.Uint16(data[6:8])
	r.NSCount = binary.BigEndian.Uint16(data[8:10])
	r.ARCount = binary.BigEndian.Uint16(data[10:12])
	r.ParseQuestion(data, r.QDCount, 12)
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
