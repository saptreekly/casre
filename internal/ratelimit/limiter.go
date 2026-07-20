package ratelimit

import (
	"context"
	"sync"
	"time"
)

// Limiter is a token-bucket rate limiter safe for concurrent use.
type Limiter struct {
	mu         sync.Mutex
	tokens     float64
	maxTokens  float64
	refillRate float64 // tokens per second
	lastRefill time.Time
}

// New creates a limiter that allows rate tokens per second.
// A rate of 0 or less disables limiting.
func New(rate float64) *Limiter {
	if rate <= 0 {
		return &Limiter{refillRate: 0}
	}
	return &Limiter{
		tokens:     rate,
		maxTokens:  rate,
		refillRate: rate,
		lastRefill: time.Now(),
	}
}

// Wait blocks until a token is available or ctx is cancelled.
func (l *Limiter) Wait(ctx context.Context) error {
	if l.refillRate <= 0 {
		return ctx.Err()
	}

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		l.mu.Lock()
		l.refill()
		if l.tokens >= 1 {
			l.tokens--
			l.mu.Unlock()
			return nil
		}
		// Time until one full token is available.
		deficit := 1 - l.tokens
		wait := time.Duration(deficit / l.refillRate * float64(time.Second))
		l.mu.Unlock()

		if wait < time.Millisecond {
			wait = time.Millisecond
		}

		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (l *Limiter) refill() {
	now := time.Now()
	elapsed := now.Sub(l.lastRefill).Seconds()
	if elapsed <= 0 {
		return
	}
	l.tokens += elapsed * l.refillRate
	if l.tokens > l.maxTokens {
		l.tokens = l.maxTokens
	}
	l.lastRefill = now
}
