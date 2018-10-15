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

var httpClient = http.DefaultClient

// SetHTTPClient sets the http.Client used by the Check function
func SetHTTPClient(client *http.Client) {
	httpClient = client
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
	hash := fmt.Sprintf("%X", sha1.Sum([]byte(password)))
	prefix, suffix := hash[0:5], hash[5:len(hash)]

	res, err := httpClient.Get("https://api.pwnedpasswords.com/range/" + prefix)
	if err != nil {
		return 0, err
	}

	defer res.Body.Close()

	return findSuffix(suffix, res.Body)
}

func findSuffix(suffix string, reader io.Reader) (uint64, error) {
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()

		if line[0:len(suffix)] == suffix {
			p := strings.SplitN(line, ":", 2)
			return strconv.ParseUint(p[1], 10, 64)
		}
	}

	if err := scanner.Err(); err != nil {
		return 0, err
	}

	return 0, nil
}
