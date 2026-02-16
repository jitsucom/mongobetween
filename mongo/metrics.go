package mongo

import (
	"time"

	"github.com/DataDog/datadog-go/statsd"
)

// metricsHelper handles metrics collection with no-op behavior when statsd is nil.
type metricsHelper struct {
	statsd  *statsd.Client
	enabled bool
}

func newMetricsHelper(sd *statsd.Client) *metricsHelper {
	return &metricsHelper{
		statsd:  sd,
		enabled: sd != nil,
	}
}

// TimingScope starts a timing measurement and returns a function to call when done.
// Returns a no-op function if metrics are disabled.
func (m *metricsHelper) TimingScope(name string, tagsFn func(err error) []string) func(err error) {
	if !m.enabled {
		return func(err error) {}
	}
	start := time.Now()
	return func(err error) {
		_ = m.statsd.Timing(name, time.Since(start), tagsFn(err), 1)
	}
}

// Timing sends a timing metric immediately.
func (m *metricsHelper) Timing(name string, duration time.Duration, tags []string) {
	if !m.enabled {
		return
	}
	_ = m.statsd.Timing(name, duration, tags, 1)
}

// Distribution sends a distribution metric.
func (m *metricsHelper) Distribution(name string, value float64, tags []string) {
	if !m.enabled {
		return
	}
	_ = m.statsd.Distribution(name, value, tags, 1)
}

// Gauge sends a gauge metric.
func (m *metricsHelper) Gauge(name string, value float64, tags []string) {
	if !m.enabled {
		return
	}
	_ = m.statsd.Gauge(name, value, tags, 1)
}
