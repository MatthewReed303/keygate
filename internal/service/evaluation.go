package service

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/tabloy/keygate/internal/license"
	"github.com/tabloy/keygate/internal/model"
	"github.com/tabloy/keygate/pkg/apperr"
)

// EvaluationStatus is the status an evaluation token is signed in.
const EvaluationStatus = "evaluation"

// evaluationsPerHour caps the tokens one machine gets for one product:
// enough for a machine restarted now and then, not for a script.
const evaluationsPerHour = 6

// evaluationLimiter counts the evaluations each (product, identifier)
// asked for in the last hour. In memory: a restart of the server forgets
// it, which costs at most one more hour's worth.
type evaluationLimiter struct {
	mu   sync.Mutex
	seen map[string][]time.Time
}

func (l *evaluationLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.seen == nil {
		l.seen = map[string][]time.Time{}
	}
	kept := l.seen[key][:0]
	for _, t := range l.seen[key] {
		if now.Sub(t) < time.Hour {
			kept = append(kept, t)
		}
	}
	if len(kept) >= evaluationsPerHour {
		l.seen[key] = kept
		return false
	}
	l.seen[key] = append(kept, now)
	return true
}

// EvaluateResult is a signed evaluation token and when it lapses.
type EvaluateResult struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"`
}

// evaluationToken signs a token of the evaluation plan for identifier:
// the plan's features, status "evaluation", valid EvaluationMinutes.
func evaluationToken(plan *model.Plan, identifier string, now time.Time, key licenseSigningKey) (*EvaluateResult, error) {
	exp := now.Add(time.Duration(plan.EvaluationMinutes) * time.Minute).Unix()
	fpr := license.Fingerprint(identifier, plan.ProductID)
	t := &license.VerifyToken{
		LicenseID:   "evaluation:" + fpr[:16],
		ProductID:   plan.ProductID,
		PlanID:      plan.ID,
		Status:      EvaluationStatus,
		Identifier:  identifier,
		Features:    featureValues(plan.Entitlements),
		IssuedAt:    now.Unix(),
		ExpiresAt:   exp,
		Fingerprint: fpr,
	}
	token, err := license.Sign(t, key)
	if err != nil {
		return nil, apperr.Internal(err)
	}
	return &EvaluateResult{Token: token, ExpiresAt: exp}, nil
}

// Evaluate issues an unlicensed machine a token of its product's
// evaluation plan. Nothing is stored: a token is all an evaluation is.
func (s *LicenseService) Evaluate(ctx context.Context, productID, identifier string) (*EvaluateResult, error) {
	plan, err := s.store.EvaluationPlan(ctx, productID)
	if err != nil {
		return nil, apperr.Internal(err)
	}
	if plan == nil {
		return nil, apperr.New(http.StatusNotFound, "NO_EVALUATION", "this product offers no evaluation")
	}
	now := time.Now()
	if !s.evaluations.allow(productID+"|"+identifier, now) {
		return nil, apperr.New(http.StatusTooManyRequests, "EVALUATION_LIMIT", "too many evaluations for this machine: try again within the hour")
	}
	return evaluationToken(plan, identifier, now, s.signingKey)
}
