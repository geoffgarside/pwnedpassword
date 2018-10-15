package pwnedpassword

import (
	"bytes"
	"testing"
)

func Test_hash(t *testing.T) {
	tests := []struct {
		Arg                    string
		WantPrefix, WantSuffix string
	}{
		{"testing", "DC724", "AF18FBDD4E59189F5FE768A5F8311527050"},
	}

	for _, tt := range tests {
		gotPrefix, gotSuffix := hash(tt.Arg)
		if gotPrefix != tt.WantPrefix {
			t.Errorf("expected hash(%q) to return prefix %q, got %q",
				tt.Arg, tt.WantPrefix, gotPrefix)
		}
		if gotSuffix != tt.WantSuffix {
			t.Errorf("expected hash(%q) to return suffix %q, got %q",
				tt.Arg, tt.WantSuffix, gotSuffix)
		}
	}
}

func Test_findSuffix(t *testing.T) {
	data := "AF18FBDD4E59189F5FE768A5F831152704F:999\n" +
		"AF18FBDD4E59189F5FE768A5F8311527050:1000\n" +
		"AF18FBDD4E59189F5FE768A5F8311527051:1001\n"

	t.Parallel()
	t.Run("Present", func(t *testing.T) {
		b := bytes.NewBufferString(data)
		c, err := findSuffix("AF18FBDD4E59189F5FE768A5F8311527050", b)
		if err != nil {
			t.Fatalf("expected findSuffix not to return err, got %v", err)
		}

		if c != 1000 {
			t.Errorf("expected findSuffix to return 1000, got %v", c)
		}
	})

	t.Run("Not Present", func(t *testing.T) {
		b := bytes.NewBufferString(data)
		c, err := findSuffix("AF18FBDD4E59189F5FE768A5F8311527056", b)
		if err != nil {
			t.Fatalf("expected findSuffix not to return err, got %v", err)
		}

		if c != 0 {
			t.Errorf("expected findSuffix to return 0, got %v", c)
		}
	})

	t.Run("Empty Line", func(t *testing.T) {
		b := bytes.NewBufferString("\n")
		c, err := findSuffix("AF18FBDD4E59189F5FE768A5F8311527056", b)
		if err != nil {
			t.Fatalf("expected findSuffix not to return err, got %v", err)
		}

		if c != 0 {
			t.Errorf("expected findSuffix to return 0, got %v", c)
		}
	})
}
