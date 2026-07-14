package cas

import "sync/atomic"

// Stats is a point-in-time snapshot of CAS operation counters.
type Stats struct {
	PutCount uint64 `json:"put_count"`
	GetCount uint64 `json:"get_count"`
	HasCount uint64 `json:"has_count"`
	BytesPut uint64 `json:"bytes_put"`
	BytesGet uint64 `json:"bytes_get"`
}

// StatsRecorder records CAS counters with atomic updates.
type StatsRecorder struct {
	putCount atomic.Uint64
	getCount atomic.Uint64
	hasCount atomic.Uint64
	bytesPut atomic.Uint64
	bytesGet atomic.Uint64
}

// RecordPut records a Put call and the bytes accepted by storage.
func (r *StatsRecorder) RecordPut(bytes int) {
	r.putCount.Add(1)
	r.RecordPutBytes(bytes)
}

// RecordPutCall records a Put call without accepted bytes.
func (r *StatsRecorder) RecordPutCall() {
	r.putCount.Add(1)
}

// RecordPutBytes records bytes accepted by storage.
func (r *StatsRecorder) RecordPutBytes(bytes int) {
	if bytes > 0 {
		r.bytesPut.Add(uint64(bytes))
	}
}

// RecordGet records a Get call and the bytes returned by storage.
func (r *StatsRecorder) RecordGet(bytes int) {
	r.getCount.Add(1)
	r.RecordGetBytes(bytes)
}

// RecordGetBytes records bytes returned by storage.
func (r *StatsRecorder) RecordGetBytes(bytes int) {
	if bytes > 0 {
		r.bytesGet.Add(uint64(bytes))
	}
}

// RecordGetCall records a Get call without returned bytes.
func (r *StatsRecorder) RecordGetCall() {
	r.getCount.Add(1)
}

// RecordHasCall records a Has call.
func (r *StatsRecorder) RecordHasCall() {
	r.hasCount.Add(1)
}

// Snapshot returns the current CAS counters.
func (r *StatsRecorder) Snapshot() Stats {
	return Stats{
		PutCount: r.putCount.Load(),
		GetCount: r.getCount.Load(),
		HasCount: r.hasCount.Load(),
		BytesPut: r.bytesPut.Load(),
		BytesGet: r.bytesGet.Load(),
	}
}

// Reset clears all CAS counters.
func (r *StatsRecorder) Reset() {
	r.putCount.Store(0)
	r.getCount.Store(0)
	r.hasCount.Store(0)
	r.bytesPut.Store(0)
	r.bytesGet.Store(0)
}
