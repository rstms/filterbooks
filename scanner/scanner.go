// filter books scanner
package scanner

import (
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"strings"
)

var SkipSenders []string = []string{
	"MAILER-DAEMON@",
	"SIEVE-DAEMON@",
}

const LINE_BUFLEN = 1024

var EMAIL_ADDRESS_BRACKETED = regexp.MustCompile(`^.*<([^@]+@[^>]+)>.*$`)
var VALID_EMAIL_ADDRESS = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

type Scanner struct {
	writer    *os.File
	reader    *os.File
	User      string
	Sender    string
	To        string
	From      string
	Book      string
	header    []string
	EOL       string
	Domain    string
	apiKey    string
	MessageId string
}

func NewScanner(writer, reader *os.File, user, sender string) *Scanner {
	log.Printf("NewScanner user='%s' sender='%s'\n", user, sender)
	return &Scanner{
		writer: writer,
		reader: reader,
		User:   user,
		Sender: sender,
		header: []string{},
		EOL:    "\n",
		apiKey: ViperGetString("api_key"),
		Domain: ViperGetString("domain"),
	}
}

func (s *Scanner) Close() {
	//log.Println("begin close")
	//defer log.Println("end close")
	bitbucket, err := os.OpenFile("/dev/null", os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	defer bitbucket.Close()
	_, err = io.Copy(bitbucket, s.reader)
	if err != nil {
		panic(err)
	}
}

func (s *Scanner) Scan() error {
	//log.Printf("begin scan")
	//defer log.Println("end scan")
	for _, prefix := range SkipSenders {
		if strings.HasPrefix(s.Sender, prefix) {
			return s.WriteMessage()
		}
	}
	enable, err := s.ReadHeader()
	if err != nil {
		return Fatal(err)
	}
	if enable {
		address := s.User + "@" + s.Domain
		book, err := LookupFilterBook(address, s.apiKey, s.From)
		if err != nil {
			return Fatal(err)
		}
		s.Book = book
		//log.Printf("filterbook: %s to=%s from=%s book=%s\n", s.MessageId, address, s.From, book)
		log.Printf("filterbook: %s\n", FormatJSON(s))
		if book != "" {
			headerLine := fmt.Sprintf("X-Address-Book: %s", book)
			s.header = append([]string{headerLine}, s.header...)
		}
	}
	err = s.WriteHeader()
	if err != nil {
		return Fatal(err)
	}
	err = s.WriteMessage()
	if err != nil {
		return Fatal(err)
	}
	return nil
}

func (s *Scanner) ReadHeaderLine() (string, error) {
	lineBuf := make([]byte, LINE_BUFLEN)
	byteBuf := make([]byte, 1)
	for i := 0; i < LINE_BUFLEN; i++ {
		count, err := s.reader.Read(byteBuf)
		if err != nil {
			return "", Fatal(err)
		}
		if count != 1 {
			return "", Fatalf("buffer underflow")
		}
		lineBuf[i] = byteBuf[0]
		if byteBuf[0] == '\n' {
			line := lineBuf[:i+1]
			//log.Printf("line: %s\n", HexDump(line))
			return string(line), nil
		}
	}
	return "", Fatalf("buffer overflow")
}

func (s *Scanner) headerValue(line string) string {
	_, value, found := strings.Cut(line, ":")
	if found {
		return strings.TrimSpace(value)
	}
	return ""
}

func (s *Scanner) ReadHeader() (bool, error) {
	//log.Println("begin ReadHeader")
	//defer log.Println("end ReadHeader")
	enable := true
	for {
		line, err := s.ReadHeaderLine()
		if err != nil {
			return false, Fatal(err)
		}
		switch {
		case strings.HasSuffix(line, "\r\n"):
			line = line[:len(line)-2]
			if s.EOL == "" {
				s.EOL = "\r\n"
			}
		case strings.HasSuffix(line, "\n"):
			line = line[:len(line)-1]
			if s.EOL == "" {
				s.EOL = "\n"
			}
		case strings.HasSuffix(line, "\r"):
			line = line[:len(line)-1]
			if s.EOL == "" {
				s.EOL = "\r"
			}
		}
		lowLine := strings.ToLower(line)
		includeHeader := true
		switch {
		case len(strings.TrimSpace(line)) == 0:
			s.header = append(s.header, line)
			return enable, nil
		case strings.HasPrefix(lowLine, "x-filter-book:"):
			includeHeader = false
		case strings.HasPrefix(lowLine, "message-id:"):
			s.MessageId = s.headerValue(line)
		case strings.HasPrefix(lowLine, "to:"):
			s.To = s.headerValue(line)
		case strings.HasPrefix(lowLine, "x-filterctl-request-id:"):
			enable = false
		case strings.HasPrefix(lowLine, "from:"):
			fromAddr, err := parseEmailAddress(lowLine)
			if err != nil {
				return false, Fatal(err)
			}
			s.From = fromAddr
		}
		if includeHeader {
			s.header = append(s.header, line)
		}
	}
	return false, Fatalf("logic error")
}

func (s *Scanner) WriteHeader() error {
	//log.Println("begin WriteHeader")
	//defer log.Println("end WriteHeader")
	for _, line := range s.header {
		_, err := s.writer.Write([]byte(line + s.EOL))
		if err != nil {
			return Fatal(err)
		}
	}
	return nil
}

func (s *Scanner) WriteMessage() error {
	//log.Println("begin WriteMessage")
	//defer log.Printf("end WriteMessage")
	_, err := io.Copy(s.writer, s.reader)
	if err != nil {
		return Fatal(err)
	}
	//log.Printf("WriteMessage: wrote %d bytes\n", count)
	return nil
}

func parseEmailAddress(line string) (string, error) {
	//log.Printf("begin parseEmailAddress('%s')\n", line)
	//defer log.Println("end parseEmailAddress")
	if strings.Contains(line, "<") {
		matches := EMAIL_ADDRESS_BRACKETED.FindStringSubmatch(line)
		if len(matches) == 2 {
			log.Printf("parseEmailAddress returning %s\n", matches[1])
			address := matches[1]
			if VALID_EMAIL_ADDRESS.MatchString(address) {
				return address, nil
			}
		}

	} else {
		_, address, found := strings.Cut(line, ":")
		if found {
			address = strings.TrimSpace(address)
			if VALID_EMAIL_ADDRESS.MatchString(address) {
				return address, nil
			}
		}
	}
	return "", fmt.Errorf("email address parse failed: %s", line)
}

func LookupFilterBook(to, apiKey, from string) (string, error) {
	books, err := ScanAddressBooks(to, apiKey, from)
	if err != nil {
		return "", Fatal(err)
	}
	var book string
	if len(books) > 0 {
		book = books[0]
	}
	return book, nil
}
