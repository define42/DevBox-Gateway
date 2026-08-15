package dashboard

import (
	"encoding/json"
	"log"
	"math"
	"mime"
	"net/http"
	"strconv"
	"strings"
)

const creationStreamMediaType = "application/x-ndjson"

type creationProgressEvent struct {
	Type        string `json:"type"`
	CopiedBytes int64  `json:"copiedBytes"`
	TotalBytes  int64  `json:"totalBytes"`
}

type creationResultEvent struct {
	Type    string `json:"type"`
	OK      bool   `json:"ok"`
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
}

// CreationStream writes incremental VM creation events to a dashboard client.
type CreationStream struct {
	w                   http.ResponseWriter
	encoder             *json.Encoder
	started             bool
	hasReportedProgress bool
	lastPercent         int
	writeErr            error
}

// NewCreationStream prepares a lazy NDJSON stream. Response headers are not
// committed until the first event is written, preserving ordinary HTTP error
// responses for failures that happen before disk copying begins.
func NewCreationStream(w http.ResponseWriter) *CreationStream {
	return &CreationStream{
		w:       w,
		encoder: json.NewEncoder(w),
	}
}

// ReportDiskCopy publishes at most one update for each displayed percentage.
// The libvirt reader reports every chunk, and flushing all of those chunks would
// add avoidable network work to the synchronous volume upload.
func (s *CreationStream) ReportDiskCopy(copiedBytes, totalBytes int64) {
	percent := creationCopyPercent(copiedBytes, totalBytes)
	if s.hasReportedProgress && percent == s.lastPercent {
		return
	}
	s.hasReportedProgress = true
	s.lastPercent = percent
	s.write(creationProgressEvent{
		Type:        "progress",
		CopiedBytes: copiedBytes,
		TotalBytes:  totalBytes,
	})
}

// Started reports whether the response has committed to the NDJSON protocol.
func (s *CreationStream) Started() bool {
	return s.started
}

// WriteResult writes the terminal creation outcome.
func (s *CreationStream) WriteResult(result ActionResponse) {
	s.write(creationResultEvent{
		Type:    "result",
		OK:      result.OK,
		Message: result.Message,
		Error:   result.Error,
	})
}

func (s *CreationStream) write(event any) {
	if s.writeErr != nil {
		return
	}
	if !s.started {
		setNoCacheHeaders(s.w)
		s.w.Header().Set("Content-Type", creationStreamMediaType+"; charset=utf-8")
		s.w.WriteHeader(http.StatusOK)
		s.started = true
	}
	if err := s.encoder.Encode(event); err != nil {
		s.writeErr = err
		log.Printf("write dashboard creation stream: %v", err)
		return
	}
	if err := http.NewResponseController(s.w).Flush(); err != nil {
		s.writeErr = err
		log.Printf("flush dashboard creation stream: %v", err)
	}
}

// AcceptsCreationStream reports whether a request explicitly opts into the
// dashboard's NDJSON creation response.
func AcceptsCreationStream(req *http.Request) bool {
	for _, header := range req.Header.Values("Accept") {
		for _, accepted := range strings.Split(header, ",") {
			mediaType, params, err := mime.ParseMediaType(strings.TrimSpace(accepted))
			if err != nil || !strings.EqualFold(mediaType, creationStreamMediaType) {
				continue
			}
			if rawQuality, ok := params["q"]; ok {
				quality, err := strconv.ParseFloat(rawQuality, 64)
				if err != nil || math.IsNaN(quality) || quality <= 0 || quality > 1 {
					continue
				}
			}
			return true
		}
	}
	return false
}

func creationCopyPercent(copiedBytes, totalBytes int64) int {
	if totalBytes <= 0 || copiedBytes <= 0 {
		return 0
	}
	if copiedBytes >= totalBytes {
		return 100
	}
	return int(float64(copiedBytes) / float64(totalBytes) * 100)
}
