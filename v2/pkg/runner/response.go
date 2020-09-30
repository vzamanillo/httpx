package runner

import (
	"strings"
	"time"
)

// Response contains the response to a server
type Response struct {
	StatusCode    int
	Headers       map[string][]string
	Data          []byte
	ContentLength int
	Raw           string
	Words         int
	Lines         int
	TLSData       *TLSData
	CSPData       *CSPData
	HTTP2         bool
	Pipeline      bool
	Duration      time.Duration
}

// GetHeader value
func (r *Response) GetHeader(name string) string {
	header, ok := r.Headers[name]
	if ok {
		return strings.Join(header, " ")
	}

	return ""
}

// GetHeaderPart with offset
func (r *Response) GetHeaderPart(name, sep string) string {
	header := r.GetHeader(name)
	if header != "" {
		return strings.Split(header, sep)[0]
	}

	return ""
}
