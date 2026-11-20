package familyprofile

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	parserassets "nexora.local/nli-v20/configs/parsers"
)

func TestReviewedProofConcurrentSuccessRunsOnce(t *testing.T) {
	product := &reviewedProduct{deadline: time.Second}
	var calls atomic.Int64
	var workers sync.WaitGroup
	for i := 0; i < 32; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			err := product.proof(context.Background(), func(ctx context.Context) error {
				calls.Add(1)
				if _, ok := ctx.Deadline(); !ok {
					t.Error("shared proof is unbounded")
				}
				return nil
			})
			if err != nil {
				t.Error(err)
			}
		}()
	}
	workers.Wait()
	if calls.Load() != 1 {
		t.Fatalf("immutable proof ran %d times", calls.Load())
	}
}

func TestReviewedProofCallerCancellationCannotPoisonSuccess(t *testing.T) {
	product := &reviewedProduct{deadline: time.Second}
	ctx, cancel := context.WithCancel(context.Background())
	err := product.proof(ctx, func(proofContext context.Context) error {
		cancel()
		if proofContext.Err() != nil {
			t.Fatal("request cancellation reached independent product proof")
		}
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("caller cancellation ignored: %v", err)
	}
	if err := product.proof(context.Background(), func(context.Context) error {
		t.Fatal("successful proof repeated after caller cancellation")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	failed := &reviewedProduct{deadline: time.Second}
	if err := failed.proof(context.Background(), func(context.Context) error { return errors.New("validation failed") }); err == nil {
		t.Fatal("failed proof accepted")
	}
	if failed.proven {
		t.Fatal("failed proof cached as approval")
	}
	if err := failed.proof(context.Background(), func(context.Context) error { return nil }); err != nil {
		t.Fatal("failed proof poisoned future validation")
	}
}

func TestReviewedCachedPackConcurrentMutationIsolation(t *testing.T) {
	assets, err := parserassets.All()
	if err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ValidatePublishedPackBytesContext(canceled, assets[0].Name, assets[0].Data); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled request accepted: %v", err)
	}
	original, err := ValidatePublishedPackBytesContext(context.Background(), assets[0].Name, assets[0].Data)
	if err != nil {
		t.Fatal(err)
	}
	wantRule, wantProvenance := original.Rules[0].Name, original.Metadata["profile_provenance"]
	var workers sync.WaitGroup
	for i := 0; i < 24; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			pack, err := ValidatePublishedPackBytesContext(context.Background(), assets[0].Name, assets[0].Data)
			if err != nil {
				t.Error(err)
				return
			}
			if pack.Rules[0].Name != wantRule || pack.Metadata["profile_provenance"] != wantProvenance {
				t.Error("another caller mutated cached product")
			}
			pack.Rules[0].Name = "caller-owned rule"
			pack.Metadata["profile_provenance"] = "caller-owned metadata"
			pack.RegressionCases[0].ExpectedPayload["caller_owned"] = true
		}()
	}
	workers.Wait()
	again, err := ValidatePublishedPackBytesContext(context.Background(), assets[0].Name, assets[0].Data)
	if err != nil {
		t.Fatal(err)
	}
	if again.Rules[0].Name != wantRule || again.Metadata["profile_provenance"] != wantProvenance || again.RegressionCases[0].ExpectedPayload["caller_owned"] != nil {
		t.Fatal("returned mutable state leaked into subsequent validation")
	}
}
