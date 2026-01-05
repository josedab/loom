// Package proxy provides a bounded worker pool for async tasks.
package proxy

import (
	"context"
	"sync"
)

// WorkerPool provides a bounded pool of workers for async task execution.
// This prevents unbounded goroutine creation under high load.
type WorkerPool struct {
	tasks   chan func()
	wg      sync.WaitGroup
	stopCh  chan struct{}
	stopped bool
	mu      sync.Mutex
}

// WorkerPoolConfig configures the worker pool.
type WorkerPoolConfig struct {
	Workers   int // Number of worker goroutines
	QueueSize int // Size of the task queue buffer
}

// DefaultWorkerPoolConfig returns sensible defaults.
func DefaultWorkerPoolConfig() WorkerPoolConfig {
	return WorkerPoolConfig{
		Workers:   10,   // 10 workers for log processing
		QueueSize: 1000, // Buffer up to 1000 pending log tasks
	}
}

// NewWorkerPool creates a new bounded worker pool.
func NewWorkerPool(cfg WorkerPoolConfig) *WorkerPool {
	if cfg.Workers <= 0 {
		cfg.Workers = 10
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 1000
	}

	wp := &WorkerPool{
		tasks:  make(chan func(), cfg.QueueSize),
		stopCh: make(chan struct{}),
	}

	// Start workers
	wp.wg.Add(cfg.Workers)
	for i := 0; i < cfg.Workers; i++ {
		go wp.worker()
	}

	return wp
}

// worker processes tasks from the queue.
func (wp *WorkerPool) worker() {
	defer wp.wg.Done()
	for {
		select {
		case <-wp.stopCh:
			return
		case task, ok := <-wp.tasks:
			if !ok {
				return
			}
			// Execute task with panic recovery
			func() {
				defer func() {
					if r := recover(); r != nil {
						// Log panic but don't crash - this is for async logging
					}
				}()
				task()
			}()
		}
	}
}

// Submit adds a task to the pool. Returns false if the pool is stopped
// or the queue is full (non-blocking).
func (wp *WorkerPool) Submit(task func()) bool {
	wp.mu.Lock()
	if wp.stopped {
		wp.mu.Unlock()
		return false
	}
	wp.mu.Unlock()

	select {
	case wp.tasks <- task:
		return true
	default:
		// Queue is full, drop the task (log tasks are best-effort)
		return false
	}
}

// SubmitWait adds a task to the pool, blocking if the queue is full.
// Returns false only if the pool is stopped.
func (wp *WorkerPool) SubmitWait(ctx context.Context, task func()) bool {
	wp.mu.Lock()
	if wp.stopped {
		wp.mu.Unlock()
		return false
	}
	wp.mu.Unlock()

	select {
	case wp.tasks <- task:
		return true
	case <-ctx.Done():
		return false
	case <-wp.stopCh:
		return false
	}
}

// Stop gracefully shuts down the worker pool.
func (wp *WorkerPool) Stop() {
	wp.mu.Lock()
	if wp.stopped {
		wp.mu.Unlock()
		return
	}
	wp.stopped = true
	wp.mu.Unlock()

	close(wp.stopCh)
	close(wp.tasks)
	wp.wg.Wait()
}

// Pending returns the number of pending tasks in the queue.
func (wp *WorkerPool) Pending() int {
	return len(wp.tasks)
}
