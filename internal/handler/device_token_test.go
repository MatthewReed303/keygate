package handler

import (
	"crypto/ed25519"
	"log/slog"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/tabloy/keygate/internal/license"
	"github.com/tabloy/keygate/internal/model"
	"github.com/tabloy/keygate/internal/service"
)

// An admin issues a device's token for a machine that cannot reach the
// server: the same activation as the machine's own, with its limit and
// idempotency, recorded as the admin's.
func TestIssueDeviceToken(t *testing.T) {
	f := newAPIFixture(t)
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	h := &AdminHandler{Store: f.s, Licenses: service.NewLicenseService(f.s, priv, slog.Default(), nil, nil)}
	id := func(v string) gin.Param { return gin.Param{Key: "id", Value: v} }
	issue := func(identifier string) (int, map[string]any) {
		return f.call(h.IssueDeviceToken, http.MethodPost, "/", `{"identifier":"`+identifier+`","label":"site PC"}`, nil, id(f.licA.ID))
	}

	code, out := issue("hw-1")
	data, _ := out["data"].(map[string]any)
	if code != http.StatusOK || data["status"] != "activated" {
		t.Fatalf("issue = %d %v, want 200 activated", code, out)
	}
	tok, err := license.Verify(data["token"].(string), license.PublicKey(priv))
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	if tok.Identifier != "hw-1" || tok.LicenseID != f.licA.ID {
		t.Errorf("token did=%q lid=%q, want hw-1 on %s", tok.Identifier, tok.LicenseID, f.licA.ID)
	}

	if _, out := issue("hw-1"); out["data"].(map[string]any)["status"] != "already_activated" {
		t.Errorf("second issue for the same device = %v, want already_activated", out)
	}
	issue("hw-2")
	issue("hw-3")
	if code, out := issue("hw-4"); code != http.StatusConflict || errCode(out) != "ACTIVATION_LIMIT" {
		t.Errorf("issue past the limit = %d %v, want 409 ACTIVATION_LIMIT", code, out)
	}

	n, err := f.s.DB.NewSelect().Model((*model.AuditLog)(nil)).
		Where("entity_id = ? AND action = 'activated' AND actor_type = 'admin'", f.licA.ID).Count(f.ctx)
	if err != nil || n != 3 {
		t.Errorf("admin activations audited = %d (%v), want 3", n, err)
	}

	if code, _ := f.call(h.IssueDeviceToken, http.MethodPost, "/", `{"identifier":"hw-9"}`, nil, id("no-such-licence")); code != http.StatusNotFound {
		t.Errorf("unknown licence = %d, want 404", code)
	}
	if code, _ := f.call(h.IssueDeviceToken, http.MethodPost, "/", `{"identifier":"   "}`, nil, id(f.licA.ID)); code != http.StatusBadRequest {
		t.Errorf("blank identifier = %d, want 400", code)
	}
}
