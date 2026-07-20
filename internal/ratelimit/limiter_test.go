package ratelimit_test

import (
	"context"
	"testing"
	"time"

	"github.com/saptreekly/casre/internal/ratelimit"
)

func TestLimiterUnlimited(t *testing.T) {
	l := ratelimit.New(0)
	ctx := context.Background()
	start := time.Now()
	for i := 0; i < 100; i++ {
		if err := l.Wait(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if time.Since(start) > 50*time.Millisecond {
		t.Fatalf("unlimited limiter took too long: %s", time.Since(start))
	}
}

func TestLimiterRate(t *testing.T) {
	l := ratelimit.New(20) // 20/sec → ~50ms per token after burst
	ctx := context.Background()
	// burn the initial burst
	for i := 0; i < 20; i++ {
		_ = l.Wait(ctx)
	}
	start := time.Now()
	for i := 0; i < 5; i++ {
		if err := l.Wait(ctx); err != nil {
			t.Fatal(err)
		}
	}
	elapsed := time.Since(start)
	if elapsed < 150*time.Millisecond {
		t.Fatalf("expected rate limiting, finished too fast: %s", elapsed)
	}
}

func TestLimiterCancel(t *testing.T) {
	l := ratelimit.New(1)
	ctx, cancel := context.WithCancel(context.Background())
	// exhaust burst
	_ = l.Wait(ctx)
	cancel()
	if err := l.Wait(ctx); err == nil {
		t.Fatal("expected context error")
	}
}
