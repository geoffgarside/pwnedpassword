package main

import (
	"os"
	"testing"
)

func Test_readPassword(t *testing.T) {
	t.Run("Arg1", func(t *testing.T) {
		pw, err := readPassword([]string{"cmd", "test"})
		if err != nil {
			t.Fatalf("expected nil err, got %v", err)
		}

		if pw != "test" {
			t.Errorf("expected password to be %q, got %q",
				"test", pw)
		}
	})

	t.Run("Prompt", func(t *testing.T) {
		pipeToStdin(t, "test\n")

		pw, err := readPassword([]string{"cmd"})
		if err != nil {
			t.Fatalf("expected nil err, got %v", err)
		}

		if pw != "test" {
			t.Errorf("expected password to be %q, got %q",
				"test", pw)
		}
	})
}

func pipeToStdin(t *testing.T, s string) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("Error getting os pipes: %v", err)
	}
	os.Stdin = r
	if _, err := w.WriteString(s); err != nil {
		t.Fatalf("Error writing to Stdin pipe: %v", err)
	}
	w.Close()
}
