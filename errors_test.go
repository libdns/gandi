package gandi

import (
	"net/http"
	"testing"
)

func doRequestWithResponse(t *testing.T, status int, body string) (gandiStatus, error) {
	t.Helper()
	original := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = original })
	http.DefaultTransport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return jsonResponse(status, body), nil
	})

	req, err := http.NewRequest(http.MethodPut, "https://api.gandi.net/v5/livedns/domains/example.com/records/www/HTTPS", nil)
	if err != nil {
		t.Fatal(err)
	}

	p := &Provider{BearerToken: "test-token"}
	return p.doRequest(req, nil)
}

// LiveDNS validation errors carry no code nor message, only a list of errors:
// they used to surface as "LiveDNS returned a 0 ()".
func TestDoRequestValidationError(t *testing.T) {
	body := `{"status": "error", "errors": [{"location": "body", "name": "items", "description": "String does not match expected pattern"}]}`

	status, err := doRequestWithResponse(t, http.StatusBadRequest, body)
	if err == nil {
		t.Fatal("expected an error")
	}

	want := "LiveDNS returned a 400 (Bad Request): body items: String does not match expected pattern"
	if err.Error() != want {
		t.Fatalf("error: got %q want %q", err.Error(), want)
	}
	if status.Code != http.StatusBadRequest {
		t.Fatalf("status code: got %d want %d", status.Code, http.StatusBadRequest)
	}
	if len(status.Errors) != 1 || status.Errors[0].Location != "body" {
		t.Fatalf("errors: got %#v", status.Errors)
	}
}

func TestDoRequestCodeAndMessage(t *testing.T) {
	status, err := doRequestWithResponse(t, http.StatusNotFound, `{"code":404,"message":"record not found"}`)
	if err == nil {
		t.Fatal("expected an error")
	}

	want := "LiveDNS returned a 404 (record not found)"
	if err.Error() != want {
		t.Fatalf("error: got %q want %q", err.Error(), want)
	}
	if status.Code != http.StatusNotFound {
		t.Fatalf("status code: got %d want %d", status.Code, http.StatusNotFound)
	}
}

// A body that is not JSON (a 403 from the gateway, for instance) must still
// report the HTTP status instead of a JSON decoding error.
func TestDoRequestNonJSONError(t *testing.T) {
	status, err := doRequestWithResponse(t, http.StatusForbidden, "<html>Forbidden</html>")
	if err == nil {
		t.Fatal("expected an error")
	}

	want := "LiveDNS returned a 403 (Forbidden)"
	if err.Error() != want {
		t.Fatalf("error: got %q want %q", err.Error(), want)
	}
	if status.Code != http.StatusForbidden {
		t.Fatalf("status code: got %d want %d", status.Code, http.StatusForbidden)
	}
}
