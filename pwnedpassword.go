package pwnedpassword

import (
	"bufio"
	"crypto/sha1"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

var (
	httpClient = http.DefaultClient
	apiURL     = "https://api.pwnedpasswords.com"
)

// SetHTTPClient sets the http.Client used by the Check function
func SetHTTPClient(client *http.Client) {
	httpClient = client
}

// SetAPI sets the base endpoint URL
func SetAPI(url string) {
	apiURL = url
}

// Check checks the password against the PwnedPasswords API.
//
// Check uses the range based k-anonymity method to avoid leaking the
// password to the API.
func Check(password string) (bool, error) {
	count, err := Count(password)
	if err != nil {
		return false, err
	}

	return count > 0, nil
}

// Count checks the password against the PwnedPasswords API and returns the number of incidences
//
// Count uses the range based k-anonymity method to avoid leaking the
// password to the API.
func Count(password string) (uint64, error) {
	prefix, suffix := hash(password)

	res, err := httpClient.Get(apiURL + "/range/" + prefix)
	if err != nil {
		return 0, err
	}

	defer res.Body.Close()

	return findSuffix(suffix, res.Body)
}

func hash(password string) (prefix, suffix string) {
	h := fmt.Sprintf("%X", sha1.Sum([]byte(password)))
	return h[:5], h[5:]
}

func findSuffix(suffix string, reader io.Reader) (uint64, error) {
	scanner := bufio.NewScanner(reader)
	suffLen := len(suffix)
	for scanner.Scan() {
		line := scanner.Text()

		if len(line) > suffLen && line[:suffLen] == suffix {
			p := strings.SplitN(line, ":", 2)
			return strconv.ParseUint(p[1], 10, 64)
		}
	}

	if err := scanner.Err(); err != nil {
		return 0, err
	}

	return 0, nil
}
