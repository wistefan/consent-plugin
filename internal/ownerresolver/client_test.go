package ownerresolver

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// testConsumer is the consuming participant forwarded for CONTRACT lookup only.
const testConsumer = "did:web:fancy-marketplace.biz"

func TestResolve_SendsBodyAndParsesClaims(t *testing.T) {
	var gotPath string
	var gotReq resolveRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotReq)
		// the resolver must not receive any caller identity
		if strings.Contains(string(raw), "authorization") || strings.Contains(string(raw), "Authorization") {
			t.Errorf("resolve request leaked a caller identity: %s", raw)
		}
		_, _ = w.Write([]byte(`{"consentRequired":true,"scheme":"identifier","claims":[{"selector":{"type":"json-pointer","value":""},"ownerId":"alice-42","dataResource":"urn:ngsi-ld:PersonalProfile:alice"}]}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL+resolvePath, 0)
	res, err := c.Resolve(context.Background(), Resource{
		Service: "mp-data-service", Method: "GET",
		Path: "/ngsi-ld/v1/entities/urn:ngsi-ld:PersonalProfile:alice", ContentType: "application/ld+json",
	}, Parties{Consumer: testConsumer}, []byte(`{"id":"urn:ngsi-ld:PersonalProfile:alice","dataOwner":"alice-42"}`))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if gotPath != resolvePath {
		t.Fatalf("posted to %q", gotPath)
	}
	if gotReq.Body == nil || gotReq.Body.Encoding != encodingJSON {
		t.Fatalf("expected json body, got %+v", gotReq.Body)
	}
	if gotReq.Resource.Service != "mp-data-service" || gotReq.Resource.Path == "" {
		t.Fatalf("resource not forwarded: %+v", gotReq.Resource)
	}
	if gotReq.Parties == nil || gotReq.Parties.Consumer != testConsumer {
		t.Fatalf("consumer not forwarded for contract lookup: %+v", gotReq.Parties)
	}
	if !res.ConsentRequired || len(res.Claims) != 1 ||
		res.Claims[0].OwnerID != "alice-42" ||
		res.Claims[0].DataResource != "urn:ngsi-ld:PersonalProfile:alice" {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestResolve_NoBodyUsesEncodingNone(t *testing.T) {
	var gotReq resolveRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotReq)
		_, _ = w.Write([]byte(`{"consentRequired":true,"claims":[{"selector":{"type":"whole"},"ownerId":"bob-7"}]}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL+resolvePath, 0)
	res, err := c.Resolve(context.Background(), Resource{Service: "file-service", Path: "/files/bob-7/x.pdf"}, Parties{}, nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if gotReq.Body == nil || gotReq.Body.Encoding != encodingNone {
		t.Fatalf("expected encoding none, got %+v", gotReq.Body)
	}
	if gotReq.Parties != nil {
		t.Fatalf("no consumer given => parties must be omitted, got %+v", gotReq.Parties)
	}
	if len(res.Claims) != 1 || res.Claims[0].OwnerID != "bob-7" || res.Claims[0].DataResource != "" {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestResolve_Non2xxIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"error":"cannot resolve owner"}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL+resolvePath, 0)
	if _, err := c.Resolve(context.Background(), Resource{Path: "/x"}, Parties{}, nil); err == nil {
		t.Fatal("expected error on non-2xx resolver response")
	}
}
