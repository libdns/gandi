package gandi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func rrsetKey(name, recType string) string {
	return name + "/" + recType
}

// gandiMock simulates LiveDNS domain + per-rrset GET/PUT for client tests.
type gandiMock struct {
	zone        string
	recordsHref string
	existing    map[string]gandiRecord
	puts        map[string]gandiRecord
	deletes     []string
}

func newGandiMock(zone string) *gandiMock {
	zone = strings.TrimRight(zone, ".")
	href := fmt.Sprintf("https://api.gandi.net/v5/livedns/domains/%s/records", zone)
	return &gandiMock{
		zone:        zone,
		recordsHref: href,
		existing:    make(map[string]gandiRecord),
		puts:        make(map[string]gandiRecord),
	}
}

func (m *gandiMock) setExisting(name, recType string, values ...string) {
	m.existing[rrsetKey(name, recType)] = gandiRecord{
		RRSetName:   name,
		RRSetType:   recType,
		RRSetTTL:    300,
		RRSetValues: slices.Clone(values),
	}
}

func (m *gandiMock) install(t *testing.T) {
	t.Helper()
	original := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = original })
	http.DefaultTransport = roundTripFunc(m.roundTrip)
}

func (m *gandiMock) roundTrip(req *http.Request) (*http.Response, error) {
	domainURL := fmt.Sprintf("https://api.gandi.net/v5/livedns/domains/%s", m.zone)

	switch req.Method {
	case http.MethodGet:
		if req.URL.String() == domainURL {
			body := fmt.Sprintf(`{"fqdn":%q,"domain_records_href":%q}`, m.zone, m.recordsHref)
			return jsonResponse(http.StatusOK, body), nil
		}
		if req.URL.String() == m.recordsHref {
			records := make([]gandiRecord, 0, len(m.existing))
			for _, rec := range m.existing {
				records = append(records, rec)
			}
			raw, err := json.Marshal(records)
			if err != nil {
				return nil, err
			}
			return jsonResponse(http.StatusOK, string(raw)), nil
		}
		if strings.HasPrefix(req.URL.String(), m.recordsHref+"/") {
			key := strings.TrimPrefix(req.URL.String(), m.recordsHref+"/")
			if rec, ok := m.existing[key]; ok {
				raw, err := json.Marshal(rec)
				if err != nil {
					return nil, err
				}
				return jsonResponse(http.StatusOK, string(raw)), nil
			}
			return jsonResponse(http.StatusNotFound, `{"code":404,"message":"record not found"}`), nil
		}

	case http.MethodPut:
		if strings.HasPrefix(req.URL.String(), m.recordsHref+"/") {
			key := strings.TrimPrefix(req.URL.String(), m.recordsHref+"/")
			b, err := io.ReadAll(req.Body)
			if err != nil {
				return nil, err
			}
			var rec gandiRecord
			if err := json.Unmarshal(b, &rec); err != nil {
				return nil, err
			}
			m.puts[key] = rec
			return jsonResponse(http.StatusNoContent, ""), nil
		}

	case http.MethodDelete:
		if strings.HasPrefix(req.URL.String(), m.recordsHref+"/") {
			key := strings.TrimPrefix(req.URL.String(), m.recordsHref+"/")
			m.deletes = append(m.deletes, key)
			return jsonResponse(http.StatusNoContent, ""), nil
		}
	}

	return nil, fmt.Errorf("unexpected request: %s %s", req.Method, req.URL.String())
}

func (m *gandiMock) lastPut(name, recType string) (gandiRecord, bool) {
	rec, ok := m.puts[rrsetKey(name, recType)]
	return rec, ok
}

func addressRecord(name string, ttl time.Duration, ip string) libdns.Address {
	return libdns.Address{
		Name: name,
		TTL:  ttl,
		IP:   netip.MustParseAddr(ip),
	}
}

func TestSetRecords(t *testing.T) {
	const ttl = time.Hour

	tests := []struct {
		name           string
		zone           string
		recordName     string
		existingValues []string
		newIP          string
	}{
		{
			name:           "subdomain replaces existing value",
			zone:           "example.com",
			recordName:     "www",
			existingValues: []string{"203.0.113.1"},
			newIP:          "203.0.113.42",
		},
		{
			name:           "apex @ replaces existing value",
			zone:           "example.com",
			recordName:     "@",
			existingValues: []string{"198.51.100.10"},
			newIP:          "198.51.100.20",
		},
		{
			name:           "no existing rrset creates single value",
			zone:           "example.com",
			recordName:     "api",
			existingValues: nil,
			newIP:          "203.0.113.5",
		},
		{
			name:           "replaces multiple existing values with one",
			zone:           "example.net",
			recordName:     "dyn",
			existingValues: []string{"203.0.113.1", "203.0.113.2"},
			newIP:          "203.0.113.99",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mock := newGandiMock(tc.zone)
			if tc.existingValues != nil {
				mock.setExisting(tc.recordName, "A", tc.existingValues...)
			}
			mock.install(t)

			p := &Provider{BearerToken: "test-token"}
			_, err := p.SetRecords(context.Background(), tc.zone, []libdns.Record{
				addressRecord(tc.recordName, ttl, tc.newIP),
			})
			if err != nil {
				t.Fatalf("SetRecords: %v", err)
			}

			sent, ok := mock.lastPut(tc.recordName, "A")
			if !ok {
				t.Fatal("expected PUT to LiveDNS")
			}
			if sent.RRSetName != tc.recordName {
				t.Fatalf("rrset_name: got %q want %q", sent.RRSetName, tc.recordName)
			}
			if len(sent.RRSetValues) != 1 || sent.RRSetValues[0] != tc.newIP {
				t.Fatalf("expected rrset %q only, got %#v", tc.newIP, sent.RRSetValues)
			}
			if sent.RRSetTTL != int(ttl.Seconds()) {
				t.Fatalf("ttl: got %d want %d", sent.RRSetTTL, int(ttl.Seconds()))
			}
		})
	}
}

func TestAppendRecords(t *testing.T) {
	const ttl = time.Hour

	tests := []struct {
		name           string
		zone           string
		recordName     string
		existingValues []string
		newIP          string
		wantValues     []string
	}{
		{
			name:           "no existing rrset creates single value",
			zone:           "example.com",
			recordName:     "api",
			existingValues: nil,
			newIP:          "203.0.113.5",
			wantValues:     []string{"203.0.113.5"},
		},
		{
			name:           "subdomain merges with existing value",
			zone:           "example.com",
			recordName:     "www",
			existingValues: []string{"203.0.113.1"},
			newIP:          "203.0.113.42",
			wantValues:     []string{"203.0.113.1", "203.0.113.42"},
		},
		{
			name:           "apex @ merges with existing value",
			zone:           "example.com",
			recordName:     "@",
			existingValues: []string{"198.51.100.10"},
			newIP:          "198.51.100.20",
			wantValues:     []string{"198.51.100.10", "198.51.100.20"},
		},
		{
			name:           "duplicate value is not added twice",
			zone:           "example.com",
			recordName:     "mail",
			existingValues: []string{"203.0.113.10"},
			newIP:          "203.0.113.10",
			wantValues:     []string{"203.0.113.10"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mock := newGandiMock(tc.zone)
			if tc.existingValues != nil {
				mock.setExisting(tc.recordName, "A", tc.existingValues...)
			}
			mock.install(t)

			p := &Provider{BearerToken: "test-token"}
			_, err := p.AppendRecords(context.Background(), tc.zone, []libdns.Record{
				addressRecord(tc.recordName, ttl, tc.newIP),
			})
			if err != nil {
				t.Fatalf("AppendRecords: %v", err)
			}

			sent, ok := mock.lastPut(tc.recordName, "A")
			if !ok {
				t.Fatal("expected PUT to LiveDNS")
			}
			if sent.RRSetName != tc.recordName {
				t.Fatalf("rrset_name: got %q want %q", sent.RRSetName, tc.recordName)
			}
			if len(sent.RRSetValues) != len(tc.wantValues) {
				t.Fatalf("values: got %#v want %#v", sent.RRSetValues, tc.wantValues)
			}
			for _, want := range tc.wantValues {
				if !slices.Contains(sent.RRSetValues, want) {
					t.Fatalf("missing %q in %#v", want, sent.RRSetValues)
				}
			}
		})
	}
}

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}

func serviceBinding(name string, priority uint16, target string) libdns.ServiceBinding {
	return libdns.ServiceBinding{
		Scheme:   "https",
		Name:     name,
		TTL:      5 * time.Minute,
		Priority: priority,
		Target:   target,
		Params:   libdns.SvcParams{"alpn": []string{"h2"}},
	}
}

// LiveDNS rejects the "." target of ServiceMode HTTPS/SVCB records ("String
// does not match expected pattern"), although RFC 9460 defines it as the owner
// name: the provider must send the owner name spelled out instead.
func TestSetRecordsServiceBindingTarget(t *testing.T) {
	tests := []struct {
		name       string
		zone       string
		recordName string
		priority   uint16
		target     string
		wantValue  string
	}{
		{
			name:       "service mode self target on a subdomain",
			zone:       "example.com.",
			recordName: "www",
			priority:   2,
			target:     ".",
			wantValue:  "2 www.example.com. alpn=h2",
		},
		{
			name:       "service mode self target on the apex",
			zone:       "example.com.",
			recordName: "@",
			priority:   1,
			target:     ".",
			wantValue:  "1 example.com. alpn=h2",
		},
		{
			name:       "zone given without trailing dot",
			zone:       "example.com",
			recordName: "www",
			priority:   2,
			target:     ".",
			wantValue:  "2 www.example.com. alpn=h2",
		},
		{
			name:       "explicit target is kept",
			zone:       "example.com.",
			recordName: "www",
			priority:   1,
			target:     "cdn.example.net.",
			wantValue:  "1 cdn.example.net. alpn=h2",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mock := newGandiMock(tc.zone)
			mock.install(t)

			p := &Provider{BearerToken: "test-token"}
			_, err := p.SetRecords(context.Background(), tc.zone, []libdns.Record{
				serviceBinding(tc.recordName, tc.priority, tc.target),
			})
			if err != nil {
				t.Fatalf("SetRecords: %v", err)
			}

			sent, ok := mock.lastPut(tc.recordName, "HTTPS")
			if !ok {
				t.Fatal("expected PUT to LiveDNS")
			}
			if len(sent.RRSetValues) != 1 || sent.RRSetValues[0] != tc.wantValue {
				t.Fatalf("expected rrset %q only, got %#v", tc.wantValue, sent.RRSetValues)
			}
		})
	}
}

// AliasMode gives "." another meaning (no service available): it must not be
// rewritten into the owner name.
func TestSetRecordsAliasModeTargetUnchanged(t *testing.T) {
	mock := newGandiMock("example.com.")
	mock.install(t)

	p := &Provider{BearerToken: "test-token"}
	_, err := p.SetRecords(context.Background(), "example.com.", []libdns.Record{
		libdns.ServiceBinding{Scheme: "https", Name: "www", TTL: 5 * time.Minute, Priority: 0, Target: "."},
	})
	if err != nil {
		t.Fatalf("SetRecords: %v", err)
	}

	sent, ok := mock.lastPut("www", "HTTPS")
	if !ok {
		t.Fatal("expected PUT to LiveDNS")
	}
	if len(sent.RRSetValues) != 1 {
		t.Fatalf("expected a single value, got %#v", sent.RRSetValues)
	}
	if fields := strings.Fields(sent.RRSetValues[0]); len(fields) < 2 || fields[1] != "." {
		t.Fatalf("expected target %q, got %q", ".", sent.RRSetValues[0])
	}
}

// Reading back a record written with the owner name spelled out must give the
// "." target the caller set, so that it recognises its own record.
func TestGetRecordsServiceBindingSelfTarget(t *testing.T) {
	mock := newGandiMock("example.com.")
	mock.setExisting("www", "HTTPS", "2 www.example.com. alpn=h2")
	mock.install(t)

	p := &Provider{BearerToken: "test-token"}
	recs, err := p.GetRecords(context.Background(), "example.com.")
	if err != nil {
		t.Fatalf("GetRecords: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("expected 1 record, got %d", len(recs))
	}
	svcb, ok := recs[0].(libdns.ServiceBinding)
	if !ok {
		t.Fatalf("expected a ServiceBinding, got %T", recs[0])
	}
	if svcb.Target != "." {
		t.Fatalf("target: got %q want %q", svcb.Target, ".")
	}
}

func TestAppendRecordsServiceBindingSelfTarget(t *testing.T) {
	mock := newGandiMock("example.com.")
	mock.install(t)

	p := &Provider{BearerToken: "test-token"}
	_, err := p.AppendRecords(context.Background(), "example.com.", []libdns.Record{
		serviceBinding("www", 2, "."),
	})
	if err != nil {
		t.Fatalf("AppendRecords: %v", err)
	}

	sent, ok := mock.lastPut("www", "HTTPS")
	if !ok {
		t.Fatal("expected PUT to LiveDNS")
	}
	if len(sent.RRSetValues) != 1 || sent.RRSetValues[0] != "2 www.example.com. alpn=h2" {
		t.Fatalf("expected rrset %q only, got %#v", "2 www.example.com. alpn=h2", sent.RRSetValues)
	}
}

func TestDeleteRecordsServiceBindingSelfTarget(t *testing.T) {
	mock := newGandiMock("example.com.")
	mock.setExisting("www", "HTTPS", "2 www.example.com. alpn=h2")
	mock.install(t)

	p := &Provider{BearerToken: "test-token"}
	_, err := p.DeleteRecords(context.Background(), "example.com.", []libdns.Record{
		serviceBinding("www", 2, "."),
	})
	if err != nil {
		t.Fatalf("DeleteRecords: %v", err)
	}

	if !slices.Contains(mock.deletes, "www/HTTPS") {
		t.Fatalf("expected DELETE of www/HTTPS, got %#v", mock.deletes)
	}
}
