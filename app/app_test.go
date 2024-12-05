package main

import "testing"

// first_expected := "abc.longassdomainname.com"
// second_expected := "def.longassdomainname.com"
var doubleDns = []byte{199, 104, 1, 0, 0, 2, 0, 0, 0, 0, 0, 0, 3, 97, 98, 99, 17, 108, 111, 110, 103, 97, 115, 115, 100, 111, 109, 97, 105, 110, 110, 97, 109, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1, 3, 100, 101, 102, 192, 16, 0, 1, 0, 1}

// first_expected := "codecrafters.io"
var singleDns = []byte{88, 195, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 12, 99, 111, 100, 101, 99, 114, 97, 102, 116, 101, 114, 115, 2, 105, 111, 0, 0, 1, 0, 1}

// first_expected := "def.codecrafters.io"
var defCodeCraftersDnsMessageWithAnswerTest = []byte{192, 48, 129, 0, 0, 1, 0, 1, 0, 0, 0, 0, 12, 99, 111, 100, 101, 99, 114, 97, 102, 116, 101, 114, 115, 2, 105, 111, 0, 0, 1, 0, 1, 12, 99, 111, 100, 101, 99, 114, 97, 102, 116, 101, 114, 115, 2, 105, 111, 0, 0, 1, 0, 1, 0, 0, 14, 16, 0, 4, 76, 76, 21, 21}

var responseFromRemote = []byte{51, 53, 129, 0, 0, 1, 0, 1, 0, 0, 0, 0, 12, 99, 111, 100, 101, 99, 114, 97, 102, 116, 101, 114, 115, 2, 105, 111, 0, 0, 1, 0, 1, 12, 99, 111, 100, 101, 99, 114, 97, 102, 116, 101, 114, 115, 2, 105, 111, 0, 0, 1, 0, 1, 0, 0, 14, 16, 0, 4, 76, 76, 21, 21}

func TestParseHeader(t *testing.T) {
	dns := NewHeader()
	err := dns.FromBytes(defCodeCraftersDnsMessageWithAnswerTest)
	if err != nil {
		t.Errorf("Had error with parsing FromBytes")
	}
	first_expected := "codecrafters.io"
	if dns.QDCount != 1 {
		t.Errorf("Found more than 1 question")
	}
	if dns.Questions[0].QName != first_expected {
		t.Errorf("Had issue parsing message, expected %s got %s", first_expected, dns.Questions[0].QName)
	}
}

func TestParseHeaderResponse(t *testing.T) {
	dns := NewHeader()
	err := dns.FromBytes(responseFromRemote)
	if err != nil {
		t.Errorf("Had error with parsing FromBytes")
	}
	first_expected := "codecrafters.io"
	if dns.QDCount != 1 {
		t.Errorf("Found more than 1 question")
	}
	if dns.Questions[0].QName != first_expected {
		t.Errorf("Had issue parsing message, expected %s got %s", first_expected, dns.Questions[0].QName)
	}
}
func TestParseResponseAnswer(t *testing.T) {
	dns := NewHeader()
	_ = dns.ParseQuestion(responseFromRemote, 1, 12)
	output := parseAnswer(responseFromRemote, 33)
	first_expected := "codecrafters.io"
	answer := Answer{
		QName:    first_expected,
		Type:     0x1,
		Class:    0x1,
		TTL:      0xE10,
		RdLength: 0x4,
		Rdata:    []byte{76, 76, 21, 21},
	}
	if output.QName != answer.QName {
		t.Errorf("Wrong QName, expected %s got %s", answer.QName, output.QName)
	}
	if output.Type != answer.Type {
		t.Errorf("Wrong Type, expected %x got %x", answer.Type, output.Type)
	}
	if output.Class != answer.Class {
		t.Errorf("Wrong Class, expected %x got %x", answer.Class, output.Class)
	}
	if output.TTL != answer.TTL {
		t.Errorf("Wrong TTL, expected %x got %x", answer.TTL, output.TTL)
	}
	if output.RdLength != answer.RdLength {
		t.Errorf("Wrong RdLength, expected %x got %x", answer.RdLength, output.RdLength)
	}
}

func TestParseAnswer(t *testing.T) {
	dns := NewHeader()
	idx := dns.ParseQuestion(defCodeCraftersDnsMessageWithAnswerTest, 1, 12)
	output := parseAnswer(defCodeCraftersDnsMessageWithAnswerTest, idx)
	first_expected := "codecrafters.io"
	answer := Answer{
		QName:    first_expected,
		Type:     0x1,
		Class:    0x1,
		TTL:      0xE10,
		RdLength: 0x4,
		Rdata:    []byte{76, 76, 21, 21},
	}
	if output.QName != answer.QName {
		t.Errorf("Wrong QName, expected %s got %s", answer.QName, output.QName)
	}
	if output.Type != answer.Type {
		t.Errorf("Wrong Type, expected %x got %x", answer.Type, output.Type)
	}
	if output.Class != answer.Class {
		t.Errorf("Wrong Class, expected %x got %x", answer.Class, output.Class)
	}
	if output.TTL != answer.TTL {
		t.Errorf("Wrong TTL, expected %x got %x", answer.TTL, output.TTL)
	}
	if output.RdLength != answer.RdLength {
		t.Errorf("Wrong RdLength, expected %x got %x", answer.RdLength, output.RdLength)
	}
}

func TestParseDoubleQuestions(t *testing.T) {
	dns := NewHeader()
	dns.ParseQuestion(doubleDns, 2, 12)
	first_expected := "abc.longassdomainname.com"
	second_expected := "def.longassdomainname.com"
	if dns.Questions[0].QName != first_expected {
		t.Errorf("Result does not match first index, got %s wanted %s", dns.Questions[0].QName, first_expected)
	}
	if dns.Questions[1].QName != second_expected {
		t.Errorf("Result does not match first index, got %s wanted %s", dns.Questions[1].QName, second_expected)
	}
}

func TestParsingSingleQuestion(t *testing.T) {
	dns := NewHeader()
	dns.ParseQuestion(singleDns, 1, 12)
	first_expected := "codecrafters.io"
	if dns.Questions[0].QName != first_expected {
		t.Errorf("Result does not match first index, got %s wanted %s", dns.Questions[0].QName, first_expected)
	}
}

func TestParsingLabel(t *testing.T) {
	output := parseLabel(doubleDns[12:12+26+1], doubleDns)
	first_expected := "abc.longassdomainname.com"
	if output != first_expected {
		t.Errorf("Parsing label failed, expected %s got %s", first_expected, output)
	}
}
