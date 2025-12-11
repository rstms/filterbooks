package scanner

import (
	"github.com/stretchr/testify/require"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setDefault(t *testing.T, key string) {
	envVar := "TEST_" + strings.ToUpper(key)
	value := os.Getenv(envVar)
	require.NotEmptyf(t, value, "missing env: %s", envVar)
	ViperSetDefault(key, value)
}

func initViper(t *testing.T) {
	configFile := filepath.Join("testdata", "config.yaml")
	if !IsFile(configFile) {
		cfg, err := os.Create(configFile)
		require.Nil(t, err)
		cfg.Close()
	}
	Init("filterbooks", Version, configFile)
	setDefault(t, "sender")
	setDefault(t, "user")
	setDefault(t, "host")
	setDefault(t, "api_key")
}

func TestScanner(t *testing.T) {
	initViper(t)
	infile, err := os.Open(filepath.Join("testdata", "message"))
	require.Nil(t, err)
	defer infile.Close()
	outfile, err := os.Create(filepath.Join("testdata", "output"))
	require.Nil(t, err)
	defer outfile.Close()
	scanner, err := NewScanner(outfile, infile)
	require.Nil(t, err)
	defer scanner.Close()
	err = scanner.Scan()
	require.Nil(t, err)
}

func TestLookup(t *testing.T) {
	initViper(t)
	_, domain, found := strings.Cut(ViperGetString("host"), ".")
	require.True(t, found)
	address := ViperGetString("user") + "@" + domain
	apiKey := ViperGetString("api_key")
	sender := ViperGetString("sender")
	book, err := ScanAddressBooks(address, sender, apiKey)
	require.Nil(t, err)
	log.Printf("book=%s\n", book)
}
