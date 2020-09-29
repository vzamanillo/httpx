package httputils

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/projectdiscovery/retryablehttp-go"
)

const (
	headerParts  = 2
	requestParts = 3
	// AllMethods defines when to use all HTTP methods
	AllMethods = "all"
)

// AllHTTPMethods contains all available HTTP methods
func AllHTTPMethods() []string {
	return []string{
		http.MethodGet,
		http.MethodHead,
		http.MethodPost,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
		http.MethodConnect,
		http.MethodOptions,
		http.MethodTrace,
	}
}

// DumpRequest to string
func DumpRequest(req *retryablehttp.Request) (string, error) {
	dump, err := httputil.DumpRequestOut(req.Request, true)

	return string(dump), err
}

// DumpResponse to string
func DumpResponse(resp *http.Response) (string, error) {
	// httputil.DumpResponse does not work with websockets
	if resp.StatusCode == http.StatusContinue {
		raw := resp.Status + "\n"
		for h, v := range resp.Header {
			raw += fmt.Sprintf("%s: %s\n", h, v)
		}
		return raw, nil
	}

	raw, err := httputil.DumpResponse(resp, true)
	return string(raw), err
}

// ParseRequest from raw string
func ParseRequest(req string, unsafe bool) (method, path string, headers map[string]string, body string, err error) {
	headers = make(map[string]string)
	reader := bufio.NewReader(strings.NewReader(req))
	s, err := reader.ReadString('\n')
	if err != nil {
		err = fmt.Errorf("could not read request: %s", err)
		return
	}
	parts := strings.Split(s, " ")
	if len(parts) < requestParts {
		err = fmt.Errorf("malformed request supplied")
		return
	}
	method = parts[0]

	for {
		line, readErr := reader.ReadString('\n')
		line = strings.TrimSpace(line)

		if readErr != nil || line == "" {
			break
		}

		// Unsafe skips all checks
		p := strings.SplitN(line, ":", headerParts)
		key := p[0]
		value := ""
		if len(p) == headerParts {
			value = p[1]
		}

		if !unsafe {
			if len(p) != headerParts {
				continue
			}

			if strings.EqualFold(key, "content-length") {
				continue
			}

			key = strings.TrimSpace(key)
			value = strings.TrimSpace(value)
		}

		headers[key] = value
	}

	// Handle case with the full http url in path. In that case,
	// ignore any host header that we encounter and use the path as request URL
	if strings.HasPrefix(parts[1], "http") {
		var parsed *url.URL
		parsed, err = url.Parse(parts[1])
		if err != nil {
			err = fmt.Errorf("could not parse request URL: %s", err)
			return
		}
		path = parts[1]
		headers["Host"] = parsed.Host
	} else {
		path = parts[1]
	}

	// Set the request body
	b, err := ioutil.ReadAll(reader)
	if err != nil {
		err = fmt.Errorf("could not read request body: %s", err)
		return
	}
	body = string(b)

	return method, path, headers, body, nil
}

// TrimURLProtocol removes the HTTP scheme from an URI
func TrimURLProtocol(targetURL string) string {
	URL := strings.TrimSpace(targetURL)
	if strings.HasPrefix(strings.ToLower(URL), "http://") || strings.HasPrefix(strings.ToLower(URL), "https://") {
		URL = URL[strings.Index(URL, "//")+2:]
	}

	return URL
}
