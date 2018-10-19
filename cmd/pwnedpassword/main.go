package main

import (
	"fmt"
	"os"

	"github.com/geoffgarside/pwnedpassword"
	"github.com/howeyc/gopass"
)

func main() {
	password, err := readPassword(os.Args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read password: %v\n", err)
		os.Exit(1)
	}

	count, err := pwnedpassword.Count(password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error checking password: scanning failed: %v\n", err)
		os.Exit(1)
	}

	switch {
	case count == 0:
		fmt.Fprintf(os.Stdout, "Password not found in pwned passwords list\n")
	case count == 1:
		fmt.Fprintf(os.Stdout, "Password found 1 time in pwned passwords list\n")
	default:
		fmt.Fprintf(os.Stdout, "Password found %d times in pwned passwords list\n", count)
	}
}

func readPassword(args []string) (string, error) {
	if len(args) == 2 && args[1] != "" {
		return args[1], nil
	}

	b, err := gopass.GetPasswdPrompt("password: ", true, os.Stdin, os.Stdout)
	if err != nil {
		return "", err
	}

	fmt.Printf("\n")
	return string(b), nil
}
