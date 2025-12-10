package scanner

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const SENDER = "user@domain.ext"

func emailAccount(t *testing.T) (string, string) {
	return os.Getenv("TEST_ADDRESS"), os.Getenv("TEST_PASSWORD")
}

func setupInput(t *testing.T, sourceFilename string) (string, string) {
	inputFile, err := os.Create(filepath.Join("testdata", "input"))
	require.Nil(t, err)
	defer inputFile.Close()
	address, password := emailAccount(t)
	user, domain, found := strings.Cut(address, "@")
	require.True(t, found)
	_, err = inputFile.Write([]byte(fmt.Sprintf("X-Filter-Book-Domain: %s\n", domain)))
	require.Nil(t, err)
	_, err = inputFile.Write([]byte(fmt.Sprintf("X-Filter-Book-Api-Key: %s\n", password)))
	require.Nil(t, err)
	sourceFile, err := os.Open(sourceFilename)
	require.Nil(t, err)
	defer sourceFile.Close()
	_, err = io.Copy(inputFile, sourceFile)
	require.Nil(t, err)
	return user, SENDER
}

func TestScanner(t *testing.T) {
	user, sender := setupInput(t, filepath.Join("testdata", "message"))
	infile, err := os.Open(filepath.Join("testdata", "input"))
	require.Nil(t, err)
	defer infile.Close()
	outfile, err := os.Create(filepath.Join("testdata", "output"))
	require.Nil(t, err)
	defer outfile.Close()
	scanner := NewScanner(outfile, infile, user, sender)
	defer scanner.Close()
	err = scanner.Scan()
	require.Nil(t, err)
}

func TestLookup(t *testing.T) {
	address, password := emailAccount(t)
	sender := os.Getenv("TEST_SENDER")
	book, err := LookupFilterBook(address, password, sender)
	require.Nil(t, err)
	log.Printf("book=%s\n", book)
}
