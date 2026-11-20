package familyprofile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	parserassets "nexora.local/nli-v20/configs/parsers"
	"nexora.local/nli-v20/internal/canonicaljson"
	parserpolicy "nexora.local/nli-v20/parser-policy"
)

type reviewedProduct struct {
	canonical []byte // Immutable, private copy of an embedded release asset.
	deadline  time.Duration
	mu        sync.Mutex
	proven    bool
}

// Only successful proofs are retained. A request cannot cancel or poison the
// shared proof, and failed validation never becomes a cached approval.
func (p *reviewedProduct) proof(ctx context.Context, validate func(context.Context) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if !p.proven {
		// Embedded product packs use a five-second execution deadline. No worker
		// goroutine is spawned; their fixed reviewed regressions run synchronously.
		proofContext, cancel := context.WithTimeout(context.Background(), p.deadline)
		err := validate(proofContext)
		if err == nil {
			err = proofContext.Err()
		}
		cancel()
		if err != nil {
			return err
		}
		p.proven = true
	}
	return ctx.Err()
}

var reviewedIndex struct {
	once     sync.Once
	products map[[32]byte]*reviewedProduct
	err      error
}

func lookupReviewedProduct(data []byte) (*reviewedProduct, error) {
	if len(data) == 0 || len(data) > parserpolicy.MaxPackSize {
		return nil, fmt.Errorf("published parser payload exceeds bounds")
	}
	reviewedIndex.once.Do(func() {
		assets, err := parserassets.All()
		if err != nil {
			reviewedIndex.err = err
			return
		}
		products := make(map[[32]byte]*reviewedProduct, len(assets))
		for _, asset := range assets {
			canonical, err := canonicaljson.Normalize(asset.Data)
			if err != nil {
				reviewedIndex.err = err
				return
			}
			var bounds struct {
				ResourceLimits parserpolicy.ResourceLimits `json:"resource_limits"`
			}
			if err := json.Unmarshal(canonical, &bounds); err != nil {
				reviewedIndex.err = err
				return
			}
			deadline := time.Duration(bounds.ResourceLimits.ExecutionDeadlineMs) * time.Millisecond
			if deadline <= 0 || deadline > 5*time.Second {
				reviewedIndex.err = fmt.Errorf("embedded product proof deadline is invalid")
				return
			}
			products[sha256.Sum256(canonical)] = &reviewedProduct{canonical: canonical, deadline: deadline}
		}
		reviewedIndex.products = products
	})
	if reviewedIndex.err != nil {
		return nil, reviewedIndex.err
	}
	canonical, err := canonicaljson.Normalize(data)
	if err != nil {
		return nil, err
	}
	product := reviewedIndex.products[sha256.Sum256(canonical)]
	if product == nil || !bytes.Equal(product.canonical, canonical) {
		return nil, nil
	}
	return product, nil
}

// ValidatePublishedPackBytesContext memoizes regression proof solely for exact
// embedded product bytes. Every returned pack is decoded afresh so callers
// cannot mutate the proof, another request's pack, or the embedded index.
func ValidatePublishedPackBytesContext(ctx context.Context, name string, data []byte) (*parserpolicy.ParserPack, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	product, err := lookupReviewedProduct(data)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if product != nil {
		err = product.proof(ctx, func(proofContext context.Context) error {
			_, err := compileContext(proofContext, name, product.canonical, false, true)
			return err
		})
		if err != nil {
			return nil, err
		}
		var pack parserpolicy.ParserPack
		if err := json.Unmarshal(product.canonical, &pack); err != nil {
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return &pack, nil
	}
	var identity struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(data, &identity); err != nil {
		return nil, err
	}
	if IsBuiltinPackID(identity.ID) {
		return nil, fmt.Errorf("protected built-in parser %q differs from the reviewed release asset", identity.ID)
	}
	return ValidateManagedPackBytesContext(ctx, name, data)
}

func exactEmbeddedPack(data []byte) bool {
	product, err := lookupReviewedProduct(data)
	return err == nil && product != nil
}
