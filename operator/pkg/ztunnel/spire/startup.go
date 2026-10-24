// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package spire

import (
	"context"
	"fmt"
	"time"

	"github.com/cilium/hive/cell"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/cilium/cilium/pkg/backoff"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// Bound startup independently of the individual connection/RPC timeout.
const (
	spireStartupTimeout = 3 * time.Minute
	logStage            = "stage"
	logDeadline         = "deadline"
)

type spireConnection struct {
	entry entryv1.EntryClient
	close func()
}

func acknowledgeServer(ctx context.Context, entry entryv1.EntryClient) error {
	_, err := entry.CountEntries(ctx, &entryv1.CountEntriesRequest{})
	return err
}

func (c *Client) run(ctx context.Context, health cell.Health) error {
	delay := backoff.Exponential{Logger: c.log, Min: 100 * time.Millisecond, Max: 10 * time.Second, Jitter: true}
	return c.runWithConnector(ctx, health, c.connect, delay.Duration)
}

func (c *Client) runWithConnector(ctx context.Context, health cell.Health,
	connect func(context.Context) (*spireConnection, error), delay func(int) time.Duration,
) error {
	startupCtx, cancel := context.WithTimeout(ctx, spireStartupTimeout)
	defer cancel()
	deadline, _ := startupCtx.Deadline()
	c.log.InfoContext(ctx, "Starting SPIRE initialization",
		logStage, "server-ack",
		logfields.Event, "startup",
		logDeadline, deadline,
		logfields.Address, c.cfg.SpireServerAddress,
		logfields.Timeout, spireStartupTimeout)
	conn, err := c.initialize(startupCtx, health, connect, delay)
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		c.log.ErrorContext(ctx, "SPIRE initialization failed",
			logStage, "server-ack",
			logfields.Event, "startup-failed",
			logfields.Error, err)
		return err
	}
	defer conn.close()
	c.entryMutex.Lock()
	c.entry = conn.entry
	c.entryMutex.Unlock()
	close(c.initialized)
	health.OK("Authenticated SPIRE server acknowledgment received")
	<-ctx.Done()
	c.entryMutex.Lock()
	c.entry = nil
	c.entryMutex.Unlock()
	return nil
}

func (c *Client) initialize(ctx context.Context, health cell.Health,
	connect func(context.Context) (*spireConnection, error), delay func(int) time.Duration,
) (*spireConnection, error) {
	start := time.Now()
	for attempt := 1; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("SPIRE startup: %w", err)
		}
		conn, err := connect(ctx)
		if err == nil {
			c.log.InfoContext(ctx, "SPIRE server acknowledged authenticated API request",
				logStage, "server-ack",
				logfields.Event, "ack",
				logfields.Attempt, attempt,
				logfields.ElapsedDuration, time.Since(start),
				logfields.Address, c.cfg.SpireServerAddress)
			return conn, nil
		}
		// These indicate invalid credentials, permissions or configuration,
		// not a dependency that simply has not finished starting.
		switch status.Code(err) {
		case codes.PermissionDenied, codes.Unauthenticated, codes.InvalidArgument, codes.FailedPrecondition:
			return nil, fmt.Errorf("SPIRE startup rejected: %w", err)
		}
		if ctx.Err() != nil {
			return nil, fmt.Errorf("SPIRE startup after %d attempts: %w", attempt, ctx.Err())
		}
		next := delay(attempt)
		deadline, hasDeadline := ctx.Deadline()
		if hasDeadline {
			next = min(next, max(time.Until(deadline), 0))
		}
		health.Degraded("Waiting for authenticated SPIRE server acknowledgment", err)
		c.log.WarnContext(ctx, "Retrying SPIRE initialization",
			logStage, "server-ack",
			logfields.Event, "retry",
			logfields.Attempt, attempt,
			logfields.ElapsedDuration, time.Since(start),
			logfields.Backoff, next,
			logDeadline, deadline,
			logfields.Address, c.cfg.SpireServerAddress,
			logfields.Error, err)
		timer := time.NewTimer(next)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, fmt.Errorf("SPIRE startup after %d attempts: %w", attempt, ctx.Err())
		case <-timer.C:
		}
	}
}
