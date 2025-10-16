// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package parallel

import (
	"context"
	"runtime"
	"sync"
	"time"
)

// ResourceMetrics holds current system resource usage
type ResourceMetrics struct {
	CPUCores       int       `json:"cpu_cores"`
	MemoryTotal    uint64    `json:"memory_total_mb"`
	MemoryUsed     uint64    `json:"memory_used_mb"`
	MemoryPercent  float64   `json:"memory_percent"`
	GoroutineCount int       `json:"goroutine_count"`
	HeapSize       uint64    `json:"heap_size_mb"`
	HeapUsed       uint64    `json:"heap_used_mb"`
	GCCount        uint32    `json:"gc_count"`
	Timestamp      time.Time `json:"timestamp"`
}

// ResourceLimits defines resource constraints
type ResourceLimits struct {
	MaxMemoryPercent float64 `json:"max_memory_percent"`
	MaxWorkers       int     `json:"max_workers"`
	MinWorkers       int     `json:"min_workers"`
	MaxFileSize      int64   `json:"max_file_size_mb"`
	MemoryThreshold  uint64  `json:"memory_threshold_mb"`
}

// DefaultResourceLimits returns sensible default limits
func DefaultResourceLimits() ResourceLimits {
	return ResourceLimits{
		MaxMemoryPercent: 80.0, // Don't use more than 80% of system memory
		MaxWorkers:       32,   // Cap workers at 32 regardless of CPU count
		MinWorkers:       2,    // Always have at least 2 workers
		MaxFileSize:      500,  // 500MB max file size for streaming
		MemoryThreshold:  1024, // 1GB threshold for memory pressure
	}
}

// ResourceMonitor tracks system resource usage
type ResourceMonitor struct {
	mu             sync.RWMutex
	currentMetrics ResourceMetrics
	limits         ResourceLimits
	ctx            context.Context
	cancel         context.CancelFunc
	updateInterval time.Duration
	callbacks      []func(ResourceMetrics)
}

// NewResourceMonitor creates a new resource monitor
func NewResourceMonitor(limits ResourceLimits) *ResourceMonitor {
	ctx, cancel := context.WithCancel(context.Background())

	rm := &ResourceMonitor{
		limits:         limits,
		ctx:            ctx,
		cancel:         cancel,
		updateInterval: 1 * time.Second,
		callbacks:      make([]func(ResourceMetrics), 0),
	}

	// Get initial metrics
	rm.updateMetrics()

	return rm
}

// Start begins monitoring system resources
func (rm *ResourceMonitor) Start() {
	go rm.monitorLoop()
}

// Stop stops the resource monitor
func (rm *ResourceMonitor) Stop() {
	rm.cancel()
}

// GetMetrics returns current resource metrics (thread-safe)
func (rm *ResourceMonitor) GetMetrics() ResourceMetrics {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.currentMetrics
}

// GetLimits returns current resource limits
func (rm *ResourceMonitor) GetLimits() ResourceLimits {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.limits
}

// SetLimits updates resource limits
func (rm *ResourceMonitor) SetLimits(limits ResourceLimits) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.limits = limits
}

// OnMetricsUpdate registers a callback for metrics updates
func (rm *ResourceMonitor) OnMetricsUpdate(callback func(ResourceMetrics)) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.callbacks = append(rm.callbacks, callback)
}

// IsMemoryPressure returns true if system is under memory pressure
func (rm *ResourceMonitor) IsMemoryPressure() bool {
	metrics := rm.GetMetrics()
	limits := rm.GetLimits()

	return metrics.MemoryPercent > limits.MaxMemoryPercent ||
		metrics.MemoryUsed > limits.MemoryThreshold
}

// ShouldReduceWorkers returns true if worker count should be reduced
func (rm *ResourceMonitor) ShouldReduceWorkers(currentWorkers int) bool {
	if currentWorkers <= rm.limits.MinWorkers {
		return false
	}

	return rm.IsMemoryPressure()
}

// ShouldIncreaseWorkers returns true if worker count can be increased
func (rm *ResourceMonitor) ShouldIncreaseWorkers(currentWorkers int) bool {
	if currentWorkers >= rm.limits.MaxWorkers {
		return false
	}

	metrics := rm.GetMetrics()

	// Only increase if memory usage is reasonable
	return metrics.MemoryPercent < (rm.limits.MaxMemoryPercent * 0.7)
}

// OptimalWorkerCount calculates optimal number of workers
func (rm *ResourceMonitor) OptimalWorkerCount(fileCount int, avgFileSize int64) int {
	metrics := rm.GetMetrics()
	limits := rm.GetLimits()

	// Base calculation on CPU cores
	cpuBasedWorkers := metrics.CPUCores

	// Adjust for memory constraints
	if rm.IsMemoryPressure() {
		cpuBasedWorkers = maxInt(cpuBasedWorkers/2, limits.MinWorkers)
	}

	// Adjust for file size (larger files need fewer workers)
	if avgFileSize > limits.MaxFileSize*1024*1024/2 { // If avg file > 250MB
		cpuBasedWorkers = maxInt(cpuBasedWorkers/2, limits.MinWorkers)
	}

	// Adjust for file count (many small files can use more workers)
	if fileCount > cpuBasedWorkers*2 && avgFileSize < 10*1024*1024 { // < 10MB files
		cpuBasedWorkers = minInt(cpuBasedWorkers*2, limits.MaxWorkers)
	}

	// Apply hard limits
	optimal := maxInt(limits.MinWorkers, minInt(cpuBasedWorkers, limits.MaxWorkers))

	return optimal
}

// monitorLoop continuously updates resource metrics
func (rm *ResourceMonitor) monitorLoop() {
	ticker := time.NewTicker(rm.updateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-rm.ctx.Done():
			return
		case <-ticker.C:
			rm.updateMetrics()
			rm.notifyCallbacks()
		}
	}
}

// updateMetrics collects current system metrics
func (rm *ResourceMonitor) updateMetrics() {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	metrics := ResourceMetrics{
		CPUCores:       runtime.NumCPU(),
		MemoryTotal:    getSystemMemory(),
		HeapSize:       memStats.Sys / 1024 / 1024,
		HeapUsed:       memStats.Alloc / 1024 / 1024,
		GoroutineCount: runtime.NumGoroutine(),
		GCCount:        memStats.NumGC,
		Timestamp:      time.Now(),
	}

	// Calculate memory usage (approximation using heap stats)
	metrics.MemoryUsed = metrics.HeapUsed
	if metrics.MemoryTotal > 0 {
		metrics.MemoryPercent = float64(metrics.MemoryUsed) / float64(metrics.MemoryTotal) * 100
	}

	rm.mu.Lock()
	rm.currentMetrics = metrics
	rm.mu.Unlock()
}

// notifyCallbacks calls all registered callbacks with current metrics
func (rm *ResourceMonitor) notifyCallbacks() {
	rm.mu.RLock()
	callbacks := make([]func(ResourceMetrics), len(rm.callbacks))
	copy(callbacks, rm.callbacks)
	metrics := rm.currentMetrics
	rm.mu.RUnlock()

	for _, callback := range callbacks {
		go callback(metrics)
	}
}

// getSystemMemory returns total system memory in MB
// This is a simplified implementation - in production you might use
// platform-specific APIs or libraries like gopsutil
func getSystemMemory() uint64 {
	// This is an approximation - Go doesn't provide direct access to total system memory
	// In production, you would use a library like gopsutil or platform-specific calls
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// Estimate system memory as roughly 4x the current heap size
	// This is very approximate and would be better replaced with actual system calls
	estimatedTotal := (memStats.Sys * 4) / 1024 / 1024

	// Ensure we return at least 1GB to avoid division by zero
	if estimatedTotal < 1024 {
		estimatedTotal = 1024
	}

	return estimatedTotal
}

// Helper functions for resource monitoring
func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ResourceStats provides summary statistics
type ResourceStats struct {
	OptimalWorkers int     `json:"optimal_workers"`
	MemoryPressure bool    `json:"memory_pressure"`
	CPUUsage       float64 `json:"cpu_usage_estimate"`
	Recommendation string  `json:"recommendation"`
}

// GetResourceStats returns current resource recommendations
func (rm *ResourceMonitor) GetResourceStats(currentWorkers, fileCount int, avgFileSize int64) ResourceStats {
	metrics := rm.GetMetrics()
	optimal := rm.OptimalWorkerCount(fileCount, avgFileSize)

	var recommendation string
	if optimal > currentWorkers {
		recommendation = "Consider increasing worker count for better performance"
	} else if optimal < currentWorkers {
		recommendation = "Consider reducing worker count to save resources"
	} else {
		recommendation = "Current worker count is optimal"
	}

	if rm.IsMemoryPressure() {
		recommendation = "System under memory pressure - reduce worker count or file batch size"
	}

	return ResourceStats{
		OptimalWorkers: optimal,
		MemoryPressure: rm.IsMemoryPressure(),
		CPUUsage:       float64(metrics.GoroutineCount) / float64(metrics.CPUCores) * 10, // Rough estimate
		Recommendation: recommendation,
	}
}
