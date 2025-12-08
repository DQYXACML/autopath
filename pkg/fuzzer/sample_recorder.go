package fuzzer

import (
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/common"
)

type sampleBucket struct {
	functionName string
	positive     []MutationSample
	negative     []MutationSample
}

func (b *sampleBucket) clone() *sampleBucket {
	if b == nil {
		return nil
	}
	cp := &sampleBucket{
		functionName: b.functionName,
	}
	if len(b.positive) > 0 {
		cp.positive = append([]MutationSample(nil), b.positive...)
	}
	if len(b.negative) > 0 {
		cp.negative = append([]MutationSample(nil), b.negative...)
	}
	return cp
}

type sampleRecorder struct {
	mu      sync.Mutex
	samples map[string]*sampleBucket // key: contract|selector (lowercase)
}

func newSampleRecorder() *sampleRecorder {
	return &sampleRecorder{
		samples: make(map[string]*sampleBucket),
	}
}

func (sr *sampleRecorder) Reset() {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	sr.samples = make(map[string]*sampleBucket)
}

func (sr *sampleRecorder) Record(
	contract common.Address,
	selector string,
	functionName string,
	params []ParameterValue,
	similarity float64,
	mutated bool,
	positive bool,
) {
	if selector == "" {
		return
	}

	key := strings.ToLower(contract.Hex()) + "|" + strings.ToLower(selector)

	sr.mu.Lock()
	defer sr.mu.Unlock()

	bucket, ok := sr.samples[key]
	if !ok {
		bucket = &sampleBucket{}
		sr.samples[key] = bucket
	}
	if bucket.functionName == "" {
		bucket.functionName = functionName
	}

	sample := MutationSample{
		Selector:     selector,
		FunctionName: bucket.functionName,
		Similarity:   similarity,
		Params:       toPublicParamValues(params),
		Mutated:      mutated,
		SampleType:   "negative",
	}
	if positive {
		sample.SampleType = "positive"
		bucket.positive = append(bucket.positive, sample)
	} else {
		bucket.negative = append(bucket.negative, sample)
	}
}

func (sr *sampleRecorder) Snapshot(contract common.Address) map[string]*sampleBucket {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	prefix := strings.ToLower(contract.Hex()) + "|"
	out := make(map[string]*sampleBucket)
	for key, bucket := range sr.samples {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		selector := strings.TrimPrefix(key, prefix)
		out[selector] = bucket.clone()
	}
	return out
}

func toPublicParamValues(params []ParameterValue) []PublicParamValue {
	if len(params) == 0 {
		return nil
	}
	out := make([]PublicParamValue, 0, len(params))
	for _, p := range params {
		out = append(out, ToPublicParamValue(p))
	}
	return out
}
