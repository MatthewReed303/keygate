package service

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/tabloy/keygate/internal/model"
)

func TestEvaluationToken(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	plan := &model.Plan{ID: "pl", ProductID: "pr", EvaluationMinutes: 120, Entitlements: []*model.Entitlement{
		{Feature: "ai", ValueType: "bool", Value: "true"},
		{Feature: "unlock.k1", ValueType: "string", Value: "sealed"},
	}}
	now := time.Unix(1_000_000, 0)
	r, err := evaluationToken(plan, "DEV", now, priv)
	if err != nil {
		t.Fatal(err)
	}
	if r.ExpiresAt != now.Unix()+120*60 {
		t.Fatalf("exp %d", r.ExpiresAt)
	}
	b64, sig, _ := strings.Cut(r.Token, ".")
	s, _ := base64.RawURLEncoding.DecodeString(sig)
	if !ed25519.Verify(priv.Public().(ed25519.PublicKey), []byte(b64), s) {
		t.Fatal("not signed by the key")
	}
	raw, _ := base64.RawURLEncoding.DecodeString(b64)
	var c map[string]any
	_ = json.Unmarshal(raw, &c)
	if c["sts"] != EvaluationStatus || c["did"] != "DEV" || c["pid"] != "pr" || c["pln"] != "pl" {
		t.Fatalf("claims %v", c)
	}
	ftr := c["ftr"].(map[string]any)
	if ftr["ai"] != true || ftr["unlock.k1"] != "sealed" {
		t.Fatalf("features %v", ftr)
	}
}

func TestEvaluationLimiter(t *testing.T) {
	var l evaluationLimiter
	now := time.Unix(1_000_000, 0)
	for i := 0; i < evaluationsPerHour; i++ {
		if !l.allow("p|a", now.Add(time.Duration(i)*time.Minute)) {
			t.Fatalf("refused the %dth", i+1)
		}
	}
	if l.allow("p|a", now.Add(10*time.Minute)) {
		t.Fatal("allowed one past the limit")
	}
	if !l.allow("p|b", now.Add(10*time.Minute)) {
		t.Fatal("another machine was refused")
	}
	if !l.allow("p|a", now.Add(61*time.Minute)) {
		t.Fatal("still refused an hour later")
	}
}
