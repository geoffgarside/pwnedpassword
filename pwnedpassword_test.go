package pwnedpassword_test

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/geoffgarside/pwnedpassword"
)

type hashes map[string][]string

func apiHandler(spec hashes) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println(r.URL.Path, r.URL.Path[:7], r.URL.Path[7:])
		if r.URL.Path[:7] != "/range/" {
			http.Error(w, "path did not match /range/", http.StatusNotFound)
			return
		}

		prefix := r.URL.Path[7:]
		suffixes, ok := spec[prefix]
		if !ok {
			panic(http.ErrAbortHandler)
		}

		for _, suff := range suffixes {
			fmt.Fprintf(w, "%s\n", suff)
		}
	})
}

func TestExported(t *testing.T) {
	srv := httptest.NewTLSServer(apiHandler(hashes{
		"DC724": []string{
			"AF18FBDD4E59189F5FE768A5F831152704F:20",
			"AF18FBDD4E59189F5FE768A5F8311527050:2650",
			"AF18FBDD4E59189F5FE768A5F8311527051:250",
		},
	}))

	defer srv.Close()

	pwnedpassword.SetAPI(srv.URL)
	pwnedpassword.SetHTTPClient(srv.Client())

	t.Parallel()
	t.Run("Count", func(t *testing.T) {
		count, err := pwnedpassword.Count("testing")

		if err != nil {
			t.Fatalf("expected Count not to return an error, got %v", err)
		}

		if count != 2650 {
			t.Errorf("expected Count to return %v, got %v", 2650, count)
		}
	})

	t.Run("Check", func(t *testing.T) {
		result, err := pwnedpassword.Check("testing")

		if err != nil {
			t.Fatalf("expected Check not to return an error, got %v", err)
		}

		if !result {
			t.Errorf("expected Check to return %v, got %v", false, result)
		}
	})

	t.Run("HTTPError", func(t *testing.T) {
		result, err := pwnedpassword.Check("panic")

		if err == nil {
			t.Fatalf("expected Check not return an error, got %v", err)
		}

		if result {
			t.Errorf("expected Check to return %v, got %v", false, result)
		}
	})
}
