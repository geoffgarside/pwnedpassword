package main

import (
	"bufio"
	"crypto/sha1"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
)

func main() {
	// TODO: If os.Args length is 1, prompt for password securely

	if len(os.Args) != 2 {
		fmt.Printf("Usage: %s password\n", os.Args[0])
		os.Exit(1)
	}

	password := os.Args[1]
	hash := fmt.Sprintf("%X", sha1.Sum([]byte(password)))

	prefix, suffix := hash[0:5], hash[5:len(hash)]

	res, err := http.Get("https://api.pwnedpasswords.com/range/" + prefix)
	if err != nil {
		fmt.Printf("Error checking password: request failed: %v\n", err)
		os.Exit(1)
	}

	count, err := findSuffix(suffix, res.Body)
	if err != nil {
		fmt.Printf("Error checking password: scanning failed: %v\n", err)
		os.Exit(1)
	}

	if count == 0 {
		fmt.Printf("Password not found in pwned passwords list\n")
	} else if count == 1 {
		fmt.Printf("Password found 1 time in pwned passwords list\n")
	} else {
		fmt.Printf("Password found %d times in pwned passwords list\n", count)
	}
}

func findSuffix(suffix string, reader io.ReadCloser) (int, error) {
	defer reader.Close()

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()

		if line[0:len(suffix)] == suffix {
			p := strings.SplitN(line, ":", 2)
			return strconv.Atoi(p[1])
		}
	}

	if err := scanner.Err(); err != nil {
		return 0, err
	}

	return 0, nil
}
