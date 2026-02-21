package policy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestOPAEngineEvaluateAllow(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"result": map[string]any{
				"allow":    true,
				"decision": "allow",
				"rule_ids": []string{"base_allow"},
			},
		})
	}))
	defer ts.Close()

	engine := NewOPAEngine(OPAConfig{
		Endpoint:   ts.URL,
		PolicyPath: "v1/data/vaol/decision",
	})

	d, err := engine.Evaluate(context.Background(), &Input{TenantID: "test", ModelName: "gpt-4o"})
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	if !d.Allow {
		t.Error("should allow")
	}
	if d.Decision != "allow" {
		t.Errorf("Decision = %q, want allow", d.Decision)
	}
}

func TestOPAEngineEvaluateDeny(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"result": map[string]any{
				"allow":    false,
				"decision": "deny",
				"rule_ids": []string{"deny_plaintext"},
				"reason":   "plaintext output not allowed",
			},
		})
	}))
	defer ts.Close()

	engine := NewOPAEngine(OPAConfig{
		Endpoint:   ts.URL,
		PolicyPath: "v1/data/vaol/decision",
	})

	d, err := engine.Evaluate(context.Background(), &Input{TenantID: "test", OutputMode: "plaintext"})
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	if d.Allow {
		t.Error("should deny")
	}
	if len(d.RuleIDs) == 0 || d.RuleIDs[0] != "deny_plaintext" {
		t.Errorf("RuleIDs = %v, want [deny_plaintext]", d.RuleIDs)
	}
}

func TestOPAEngineEvaluateServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("OPA crashed"))
	}))
	defer ts.Close()

	engine := NewOPAEngine(OPAConfig{
		Endpoint:   ts.URL,
		PolicyPath: "v1/data/vaol/decision",
	})

	_, err := engine.Evaluate(context.Background(), &Input{TenantID: "test"})
	if err == nil {
		t.Fatal("should fail with server error")
	}
	if !strings.Contains(err.Error(), "OPA returned status 500") {
		t.Errorf("error should contain 'OPA returned status 500', got: %v", err)
	}
}

func TestOPAEngineEvaluateNilResult(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"result":null}`))
	}))
	defer ts.Close()

	engine := NewOPAEngine(OPAConfig{
		Endpoint:   ts.URL,
		PolicyPath: "v1/data/vaol/decision",
	})

	_, err := engine.Evaluate(context.Background(), &Input{TenantID: "test"})
	if err == nil {
		t.Fatal("should fail with nil result")
	}
	if !strings.Contains(err.Error(), "OPA returned nil result") {
		t.Errorf("error should contain 'OPA returned nil result', got: %v", err)
	}
}

func TestOPAEngineEvaluateTimeout(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	engine := NewOPAEngine(OPAConfig{
		Endpoint:   ts.URL,
		PolicyPath: "v1/data/vaol/decision",
		Timeout:    50 * time.Millisecond,
	})

	_, err := engine.Evaluate(context.Background(), &Input{TenantID: "test"})
	if err == nil {
		t.Fatal("should fail with timeout")
	}
	if !strings.Contains(err.Error(), "calling OPA") {
		t.Errorf("error should contain 'calling OPA', got: %v", err)
	}
}

func TestOPAEngineMetadata(t *testing.T) {
	engine := NewOPAEngine(OPAConfig{
		Endpoint:       "http://localhost:8181",
		PolicyPath:     "v1/data/vaol/decision",
		PolicyBundleID: "vaol-policies-v3",
		PolicyHash:     "sha256:cafebabe",
	})

	if engine.PolicyHash() != "sha256:cafebabe" {
		t.Errorf("PolicyHash = %q, want sha256:cafebabe", engine.PolicyHash())
	}
	if engine.PolicyBundleID() != "vaol-policies-v3" {
		t.Errorf("PolicyBundleID = %q, want vaol-policies-v3", engine.PolicyBundleID())
	}
	if engine.Version() != "opa-rest/1.0" {
		t.Errorf("Version = %q, want opa-rest/1.0", engine.Version())
	}
}

func TestDenyAllEngineMetadata(t *testing.T) {
	deny := NewDenyAllEngine("test_code", "test reason")

	if deny.PolicyHash() != "" {
		t.Errorf("PolicyHash = %q, want empty", deny.PolicyHash())
	}
	if deny.PolicyBundleID() != "static-deny" {
		t.Errorf("PolicyBundleID = %q, want static-deny", deny.PolicyBundleID())
	}
	if deny.Version() != "static/1.0" {
		t.Errorf("Version = %q, want static/1.0", deny.Version())
	}
}

func TestDenyAllEngineDefaults(t *testing.T) {
	deny := NewDenyAllEngine("", "")
	d, _ := deny.Evaluate(context.Background(), &Input{})

	if d.DecisionReasonCode != "policy_denied" {
		t.Errorf("DecisionReasonCode = %q, want policy_denied", d.DecisionReasonCode)
	}
	if d.Reason != "request denied by static policy" {
		t.Errorf("Reason = %q, want 'request denied by static policy'", d.Reason)
	}
}

func TestNoopEngineMetadata(t *testing.T) {
	noop := &NoopEngine{}

	if noop.PolicyHash() != "" {
		t.Errorf("PolicyHash = %q, want empty", noop.PolicyHash())
	}
	if noop.PolicyBundleID() != "" {
		t.Errorf("PolicyBundleID = %q, want empty", noop.PolicyBundleID())
	}
	if noop.Version() != "noop/1.0" {
		t.Errorf("Version = %q, want noop/1.0", noop.Version())
	}
}
