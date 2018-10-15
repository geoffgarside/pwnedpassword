package main

import (
	"fmt"
	"os"

	"github.com/geoffgarside/pwnedpassword"
	"github.com/howeyc/gopass"
)

func main() {
	var password string

	if len(os.Args) == 1 {
		var err error

		fmt.Printf("password: ")
		os.Stdout.Sync()

		b, err := gopass.GetPasswdMasked()
		if err != nil {
			fmt.Printf("Failed to read password: %v\n", err)
			os.Exit(1)
		}

		password = string(b)
		fmt.Printf("\n")
	} else {
		password = os.Args[1]
	}

	count, err := pwnedpassword.Count(password)
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
