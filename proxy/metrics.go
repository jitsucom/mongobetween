package proxy

import (
	"time"

	"github.com/DataDog/datadog-go/statsd"
)

// RequestMetrics handles metrics collection for a single request.
// All methods are no-ops when statsd is nil.
type RequestMetrics struct {
	statsd  *statsd.Client
	tags    []string
	start   time.Time
	enabled bool
}

// NewRequestMetrics creates a new RequestMetrics. Returns a no-op instance if statsd is nil.
func NewRequestMetrics(sd *statsd.Client) *RequestMetrics {
	if sd == nil {
		return &RequestMetrics{enabled: false}
	}
	return &RequestMetrics{
		statsd:  sd,
		tags:    make([]string, 0, 8),
		start:   time.Now(),
		enabled: true,
	}
}

// AddRequestTags adds request-related tags (op_code, is_master, command, collection, unacknowledged).
func (m *RequestMetrics) AddRequestTags(opCode int32, isMaster bool, command, collection string, unacknowledged bool) {
	if !m.enabled {
		return
	}
	m.tags = append(m.tags,
		opCodeTag(tagPrefixRequestOpCode, opCode),
		boolTag(tagIsMasterTrue, tagIsMasterFalse, isMaster),
		tagPrefixCommand+command,
		tagPrefixCollection+collection,
		boolTag(tagUnacknowledgedTrue, tagUnacknowledgedFalse, unacknowledged),
	)
}

// AddResponseTag adds response op_code tag.
func (m *RequestMetrics) AddResponseTag(opCode int32) {
	if !m.enabled {
		return
	}
	m.tags = append(m.tags, opCodeTag(tagPrefixResponseOpCode, opCode))
}

// AddAddressTag adds address tag.
func (m *RequestMetrics) AddAddressTag(address string) {
	if !m.enabled {
		return
	}
	m.tags = append(m.tags, tagPrefixAddress+address)
}

// Tags returns the accumulated tags. Returns nil if disabled.
func (m *RequestMetrics) Tags() []string {
	if !m.enabled {
		return nil
	}
	return m.tags
}

// Finish sends the handle_message timing metric.
func (m *RequestMetrics) Finish(err error) {
	if !m.enabled {
		return
	}
	m.tags = append(m.tags, boolTag(tagSuccessTrue, tagSuccessFalse, err == nil))
	_ = m.statsd.Timing("handle_message", time.Since(m.start), m.tags, 1)
}
