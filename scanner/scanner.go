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

const Version = "0.1.17"

var SkipSenders []string = []string{
	"MAILER-DAEMON@",
	"SIEVE-DAEMON@",
}

const LINE_BUFLEN = 1024

var BRACKETED_TEXT = regexp.MustCompile(`^.*<([^>]+)>.*$`)
var VALID_EMAIL_ADDRESS = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

type Response struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type ScanResponse struct {
	Response
	Whitelisted bool     `json:"Whitelisted"`
	Book        string   `json:"Book"`
	Books       []string `json:"Books"`
}

type Scanner struct {
	writer    *os.File
	reader    *os.File
	Host      string
	User      string
	Sender    string
	To        string
	From      string
	Book      string
	EOL       string
	Address   string
	MessageId string
	header    []string
	apiKey    string
	verbose   bool
	debug     bool
	client    APIClient
}

func NewScanner(url string, writer, reader *os.File) (*Scanner, error) {
	s := Scanner{
		writer:  writer,
		reader:  reader,
		header:  []string{},
		EOL:     "\n",
		Host:    ViperGetString("host"),
		User:    ViperGetString("user"),
		Sender:  ViperGetString("sender"),
		verbose: ViperGetBool("verbose"),
	}
	if s.verbose {
		log.Printf("filterbooks v%s url=%s host=%s user=%s sender=%s\n", Version, url, s.Host, s.User, s.Sender)
	}
	if s.Host == "" {
		return nil, Fatalf("missing host")
	}
	if s.User == "" {
		return nil, Fatalf("missing user")
	}
	if s.Sender == "" {
		return nil, Fatalf("missing sender")
	}
	var err error
	s.client, err = NewAPIClient("", url, "", "", "", nil)
	if err != nil {
		return nil, Fatal(err)
	}
	return &s, nil
}

func (s *Scanner) Close() {
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

	for _, prefix := range SkipSenders {
		if strings.HasPrefix(s.Sender, prefix) {
			if s.verbose {
				log.Printf("ignoring %s message\n", s.Sender)
			}
			_, err := s.WriteMessage()
			return err
		}
	}

	_, domain, domainFound := strings.Cut(s.Host, ".")
	if !domainFound {
		return Fatalf("failed parsing domain from Host: %s", s.Host)
	}
	s.Address = s.User + "@" + domain

	enable, err := s.ReadHeader()
	if err != nil {
		return Fatal(err)
	}
	if enable {
		err := s.ScanAddressBooks(s.Address, s.From)
		if err != nil {
			return Fatal(err)
		}
	}
	count, err := s.WriteHeader()
	if err != nil {
		return Fatal(err)
	}
	if s.verbose {
		log.Printf("wrote %d header bytes", count)
	}
	count, err = s.WriteMessage()
	if err != nil {
		return Fatal(err)
	}
	if s.verbose {
		log.Printf("wrote %d message bytes", count)
	}
	return nil
}

func (s *Scanner) AddHeaderLine(headerLine string) {
	if s.verbose {
		log.Printf("adding: %s\n", headerLine)
	}
	s.header = append([]string{headerLine}, s.header...)
	return
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
			return string(line), nil
		}
	}
	return "", Fatalf("buffer overflow")
}

func (s *Scanner) ReadHeader() (bool, error) {
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
		default:
			return false, Fatalf("unexpected line ending: %s\n", HexDump([]byte(line)))
		}
		lowLine := strings.ToLower(line)
		includeHeader := true
		switch {
		case len(strings.TrimSpace(line)) == 0:
			s.header = append(s.header, line)
			return enable, nil
		case strings.HasPrefix(lowLine, "x-address-book:"):
			if s.verbose {
				log.Printf("removing: %s\n", line)
			}
			includeHeader = false
		case strings.HasPrefix(lowLine, "message-id:"):
			s.MessageId = s.bracketedText(s.headerValue(line))
			log.Printf("Message-Id: %s\n", s.MessageId)
		case strings.HasPrefix(lowLine, "to:"):
			toAddr, err := s.parseEmailAddress(lowLine)
			if err != nil {
				return false, Fatal(err)
			}
			s.To = toAddr
		case strings.HasPrefix(lowLine, "x-filterctl-request-id:"):
			if s.verbose {
				log.Println("ignoring filterctl request")
			}
			enable = false
		case strings.HasPrefix(lowLine, "from:"):
			fromAddr, err := s.parseEmailAddress(lowLine)
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

func (s *Scanner) WriteHeader() (int64, error) {
	var count int64
	for _, line := range s.header {
		if s.verbose {
			log.Printf("WriteHeader: %s\n", line)
		}
		count += int64(len(line) + len(s.EOL))
		_, err := s.writer.Write([]byte(line + s.EOL))
		if err != nil {
			return 0, Fatal(err)
		}
	}
	return count, nil
}

func (s *Scanner) WriteMessage() (int64, error) {
	count, err := io.Copy(s.writer, s.reader)
	if err != nil {
		return 0, Fatal(err)
	}
	return count, nil
}

func (s *Scanner) headerValue(line string) string {
	var ret string
	_, value, found := strings.Cut(line, ":")
	if found {
		ret = strings.TrimSpace(value)
	}
	if s.debug {
		log.Printf("headerValue(%s) returning '%s'\n", line, ret)
	}
	return ret
}

func (s *Scanner) bracketedText(line string) string {
	var ret string
	matches := BRACKETED_TEXT.FindStringSubmatch(line)
	if len(matches) == 2 {
		ret = matches[1]
	} else {
		ret = line
	}
	if s.debug {
		log.Printf("bracketedText(%s) returning '%s'\n", line, ret)
	}
	return ret
}

func (s *Scanner) parseEmailAddress(line string) (string, error) {
	address := s.bracketedText(s.headerValue(line))
	if VALID_EMAIL_ADDRESS.MatchString(address) {
		if s.debug {
			log.Printf("parseEmailAddress(%s) returning '%s'\n", line, address)
		}
		return address, nil
	}
	return "", Fatalf("failed address parse: %s", line)
}

func (s *Scanner) ScanAddressBooks(username, fromAddress string) error {

	var response ScanResponse
	_, err := s.client.Get(fmt.Sprintf("/filterctl/scan/%s/%s/", username, fromAddress), &response)
	if err != nil {
		return Fatal(err)
	}
	if !response.Success {
		return Fatalf("scan request failed: %v\n", response.Message)
	}
	if response.Whitelisted {
		s.AddHeaderLine("X-Whitelisted: yes")
	}
	if response.Book != "" {
		s.AddHeaderLine(fmt.Sprintf("X-FilterBook: %s", response.Book))
	}
	s.AddHeaderLine(fmt.Sprintf("X-FilterBooks: %s", strings.Join(response.Books, ",")))
	return nil
}
