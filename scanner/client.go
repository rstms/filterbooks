package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/rstms/rspamd-classes/classes"
	"io/ioutil"
	"net/http"
	"slices"
)

const RESCAND_URL = "https://127.0.0.1:2017"

type Response struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type UserDumpResponse struct {
	Response
	Password string              `json:"Password"`
	Classes  []classes.SpamClass `json:"Classes"`
	Books    map[string][]string `json:"Books"`
}

type FilterControlClient struct {
	apiKey string
	client *http.Client
}

func ScanAddressBooks(username, apiKey, address string) ([]string, error) {

	c := FilterControlClient{
		client: &http.Client{},
		apiKey: apiKey,
	}
	var response UserDumpResponse
	err := c.get(fmt.Sprintf("/userdump/%s/", username), &response)
	if err != nil {
		return nil, Fatal(err)
	}
	if !response.Success {
		return nil, Fatalf("scan request failed: %v\n", response.Message)
	}
	books := []string{}
	for book, addrs := range response.Books {
		for _, addr := range addrs {
			if addr == address {
				books = append(books, book)
			}
		}
	}
	slices.Sort(books)
	return books, nil
}

func (c *FilterControlClient) request(method, path string, data *[]byte) (*http.Request, error) {
	var body *bytes.Buffer
	if data == nil {
		body = bytes.NewBuffer([]byte{})
	} else {
		body = bytes.NewBuffer(*data)
	}
	req, err := http.NewRequest(method, RESCAND_URL+path, body)
	if err != nil {
		return nil, Fatalf("failed creating %s request: %v", method, err)
	}
	// we connect directly to rescand on localhost
	req.Header.Set("X-Api-Key", c.apiKey)
	req.Header.Set("X-Real-Ip", "127.0.0.1")
	if data != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

func (c *FilterControlClient) get(path string, ret interface{}) error {
	req, err := c.request("GET", path, nil)
	if err != nil {
		return Fatalf("failed creating GET request: %v", err)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return Fatalf("GET %s failed: %v", path, err)
	}
	defer resp.Body.Close()
	return c.handleResponse("GET", path, resp, ret)
}

func (c *FilterControlClient) handleResponse(method, path string, resp *http.Response, ret interface{}) error {
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return Fatalf("%s %s failed reading response body: %v", method, path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Fatalf("Error: %s %s '%s'\n%s", method, path, resp.Status, FormatJSON(body))
	}
	if len(body) == 0 {
		return nil
	}
	err = json.Unmarshal(body, ret)
	if err != nil {
		return Fatalf("failed decoding response: %v\n%v", err, string(body))
	}
	return nil
}
