package handler

import (
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/tabloy/keygate/internal/model"
)

// An offline plan binds licences to devices that never check in, so it
// is refused where that cannot work: a product without activations, or
// a floating plan, whether made so at creation or by a later edit.
func TestOfflinePlanNeedsDevicesAndStandardModel(t *testing.T) {
	f := newAPIFixture(t)
	h := &AdminHandler{Store: f.s}
	id := func(v string) gin.Param { return gin.Param{Key: "id", Value: v} }
	plan := func(productID, slug, extra string) string {
		return `{"product_id":"` + productID + `","name":"Air","slug":"` + slug + `-` + f.suffix + `","license_type":"perpetual","offline":true` + extra + `}`
	}

	code, out := f.call(h.CreatePlan, http.MethodPost, "/", plan(f.prodA.ID, "air", ""), nil)
	if code != http.StatusCreated {
		t.Fatalf("offline plan = %d %v, want 201", code, out)
	}
	if data, _ := out["data"].(map[string]any); data["offline"] != true {
		t.Errorf("created plan offline = %v, want true", data["offline"])
	}

	if code, out := f.call(h.CreatePlan, http.MethodPost, "/", plan(f.prodA.ID, "air-floating", `,"license_model":"floating"`), nil); code != http.StatusBadRequest {
		t.Errorf("offline floating plan = %d %v, want 400", code, out)
	}

	saas := &model.Product{Name: "Web", Slug: "api-saas-" + f.suffix, Type: "saas"}
	if err := f.s.CreateProduct(f.ctx, saas); err != nil {
		t.Fatal(err)
	}
	if code, out := f.call(h.CreatePlan, http.MethodPost, "/", plan(saas.ID, "air-saas", ""), nil); code != http.StatusBadRequest || errCode(out) != "INCOMPATIBLE_PRODUCT_TYPE" {
		t.Errorf("offline plan on a saas product = %d %v, want 400 INCOMPATIBLE_PRODUCT_TYPE", code, out)
	}

	if code, out := f.call(h.UpdatePlan, http.MethodPut, "/", `{"offline":true}`, nil, id(f.planA.ID)); code != http.StatusOK {
		t.Fatalf("make plan offline = %d %v, want 200", code, out)
	}
	if code, out := f.call(h.UpdatePlan, http.MethodPut, "/", `{"license_model":"floating"}`, nil, id(f.planA.ID)); code != http.StatusBadRequest {
		t.Errorf("make offline plan floating = %d %v, want 400", code, out)
	}
	if code, out := f.call(h.UpdatePlan, http.MethodPut, "/", `{"offline":false,"license_model":"floating"}`, nil, id(f.planA.ID)); code != http.StatusOK {
		t.Errorf("online again and floating = %d %v, want 200", code, out)
	}
}
