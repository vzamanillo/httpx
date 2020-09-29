package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/logrusorgru/aurora"
	_ "github.com/projectdiscovery/fdmax/autofdmax"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/httpx/v2/pkg/cache"
	customport "github.com/projectdiscovery/httpx/v2/pkg/customports"
	"github.com/projectdiscovery/httpx/v2/pkg/runner"
	"github.com/projectdiscovery/httpx/v2/pkg/utils/fileutils"
	"github.com/projectdiscovery/httpx/v2/pkg/utils/httputils"
	"github.com/projectdiscovery/httpx/v2/pkg/utils/iputils"
	"github.com/projectdiscovery/httpx/v2/pkg/utils/sliceutils"
	"github.com/projectdiscovery/httpx/v2/pkg/utils/stringutils"
	"github.com/projectdiscovery/mapcidr"
	"github.com/projectdiscovery/rawhttp"
	"github.com/remeh/sizedwaitgroup"
)

const (
	maxFileNameLenght = 255
	tokenParts        = 2
	one               = 1
	two               = 2
)

// TODO, move this to pkg/runner/runner.go
func main() {
	options := runner.ParseOptions()

	httpxOptions := runner.DefaultClientOptions
	httpxOptions.Timeout = time.Duration(options.Timeout) * time.Second
	httpxOptions.RetryMax = options.Retries
	httpxOptions.FollowRedirects = options.FollowRedirects
	httpxOptions.FollowHostRedirects = options.FollowHostRedirects
	httpxOptions.HTTPProxy = options.HTTPProxy
	httpxOptions.Unsafe = options.Unsafe
	httpxOptions.RequestOverride = runner.RequestOverride{URIPath: options.RequestURI}

	var key, value string
	httpxOptions.CustomHeaders = make(map[string]string)
	for _, customHeader := range options.CustomHeaders {
		tokens := strings.SplitN(customHeader, ":", two)
		// rawhttp skips all checks
		if options.Unsafe {
			httpxOptions.CustomHeaders[customHeader] = ""
			continue
		}

		// Continue normally
		if len(tokens) < two {
			continue
		}
		key = strings.TrimSpace(tokens[0])
		value = strings.TrimSpace(tokens[1])
		httpxOptions.CustomHeaders[key] = value
	}

	var scanopts scanOptions

	if options.InputRawRequest != "" {
		var rawRequest []byte
		rawRequest, err := ioutil.ReadFile(options.InputRawRequest)
		if err != nil {
			gologger.Fatalf("Could not read raw request from '%s': %s\n", options.InputRawRequest, err)
		}

		rrMethod, rrPath, rrHeaders, rrBody, err := httputils.ParseRequest(string(rawRequest), options.Unsafe)
		if err != nil {
			gologger.Fatalf("Could not parse raw request: %s\n", err)
		}
		scanopts.Methods = append(scanopts.Methods, rrMethod)
		scanopts.RequestURI = rrPath
		for name, value := range rrHeaders {
			httpxOptions.CustomHeaders[name] = value
		}
		scanopts.RequestBody = rrBody
		options.RawRequest = string(rawRequest)
	}

	// disable automatic host header for rawhttp if manually specified
	if options.Unsafe {
		for name := range hp.CustomHeaders {
			nameLower := strings.TrimSpace(strings.ToLower(name))
			if strings.HasPrefix(nameLower, "host") {
				rawhttp.AutomaticHostHeader(false)
			}
		}
	}

	if strings.EqualFold(options.Methods, httputils.AllMethods) {
		scanopts.Methods = httputils.AllHTTPMethods()
	} else if options.Methods != "" {
		scanopts.Methods = append(scanopts.Methods, stringutils.SplitAndTrimSpaces(options.Methods, ",")...)
	}

	if len(scanopts.Methods) == 0 {
		scanopts.Methods = append(scanopts.Methods, http.MethodGet)
	}

	scanopts.VHost = options.VHost
	scanopts.ExtractTitle = options.ExtractTitle
	scanopts.StatusCode = options.StatusCode
	scanopts.Location = options.Location
	scanopts.ContentLength = options.ContentLength
	scanopts.StoreResponse = options.StoreResponse
	scanopts.StoreResponseDir = options.StoreResponseDir
	scanopts.OutputServerHeader = options.OutputServerHeader
	scanopts.NoColor = options.NoColor
	scanopts.ResponseInStdout = options.ResponseInStdout
	scanopts.OutputWebSocket = options.OutputWebSocket
	scanopts.TLSProbe = options.TLSProbe
	scanopts.CSPProbe = options.CSPProbe
	if options.RequestURI != "" {
		scanopts.RequestURI = options.RequestURI
	}
	scanopts.OutputContentType = options.OutputContentType
	scanopts.RequestBody = options.RequestBody
	scanopts.Unsafe = options.Unsafe
	scanopts.Pipeline = options.Pipeline
	scanopts.HTTP2Probe = options.HTTP2Probe
	scanopts.OutputMethod = options.OutputMethod
	scanopts.OutputIP = options.OutputIP
	scanopts.OutputCName = options.OutputCName
	scanopts.OutputCDN = options.OutputCDN
	scanopts.OutputResponseTime = options.OutputResponseTime

	// output verb if more than one is specified
	if len(scanopts.Methods) > 1 && !options.Silent {
		scanopts.OutputMethod = true
	}

	// Try to create output folder if it doesnt exist
	if options.StoreResponse && !fileutils.FolderExists(options.StoreResponseDir) {
		if err := os.MkdirAll(options.StoreResponseDir, os.ModePerm); err != nil {
			gologger.Fatalf("Could not create output directory '%s': %s\n", options.StoreResponseDir, err)
		}
	}

	// output routine
	wgoutput := sizedwaitgroup.New(1)
	wgoutput.Add()
	output := make(chan Result)
	go func(output chan Result) {
		defer wgoutput.Done()

		var f *os.File
		if options.Output != "" {
			var err error
			f, err = os.Create(options.Output)
			if err != nil {
				gologger.Fatalf("Could not create output file '%s': %s\n", options.Output, err)
			}
			//nolint:errcheck // this method needs a small refactor to reduce complexity
			defer f.Close()
		}
		for r := range output {
			if r.err != nil {
				gologger.Debugf("Failure '%s': %s\n", r.URL, r.err)
				continue
			}

			// apply matchers and filters
			if len(options.FilterStatusCode) > 0 && sliceutils.IntSliceContains(options.FilterStatusCode, r.StatusCode) {
				continue
			}
			if len(options.FilterContentLength) > 0 && sliceutils.IntSliceContains(options.FilterContentLength, r.ContentLength) {
				continue
			}
			if options.FilterRegex != nil && options.FilterRegex.MatchString(r.raw) {
				continue
			}
			if options.OutputFilterString != "" && strings.Contains(strings.ToLower(r.raw), options.OutputFilterString) {
				continue
			}
			if len(options.MatchStatusCode) > 0 && !sliceutils.IntSliceContains(options.MatchStatusCode, r.StatusCode) {
				continue
			}
			if len(options.MatchContentLength) > 0 && !sliceutils.IntSliceContains(options.MatchContentLength, r.ContentLength) {
				continue
			}
			if options.MatchRegex != nil && !options.MatchRegex.MatchString(r.raw) {
				continue
			}
			if options.OutputMatchString != "" && !strings.Contains(strings.ToLower(r.raw), options.OutputMatchString) {
				continue
			}

			row := r.str
			if options.JSONOutput {
				row = r.JSON()
			}

			gologger.Silentf("%s\n", row)
			if f != nil {
				//nolint:errcheck // this method needs a small refactor to reduce complexity
				f.WriteString(row + "\n")
			}
		}
	}(output)

	wg := sizedwaitgroup.New(options.Threads)
	var scanner *bufio.Scanner

	// check if file has been provided
	if fileutils.FileExists(options.InputFile) {
		finput, err := os.Open(options.InputFile)
		if err != nil {
			gologger.Fatalf("Could read input file '%s': %s\n", options.InputFile, err)
		}
		scanner = bufio.NewScanner(finput)
		defer func() {
			err := finput.Close()
			if err != nil {
				gologger.Fatalf("Could close input file '%s': %s\n", options.InputFile, err)
			}
		}()
	} else if fileutils.HasStdin() {
		scanner = bufio.NewScanner(os.Stdin)
	} else {
		gologger.Fatalf("No input provided")
	}

	hp, err := runner.New(&httpxOptions)
	if err != nil {
		gologger.Fatalf("Could not create httpx instance: %s\n", err)
	}

	for scanner.Scan() {
		process(scanner.Text(), &wg, hp, runner.HTTPS, &scanopts, output)
	}

	if err := scanner.Err(); err != nil {
		gologger.Fatalf("Read error on standard input: %s", err)
	}

	wg.Wait()

	close(output)

	wgoutput.Wait()
}

func process(t string, wg *sizedwaitgroup.SizedWaitGroup, hp *runner.HTTPX, protocol string, scanopts *scanOptions, output chan Result) {
	for target := range targets(httputils.TrimURLProtocol(t)) {
		// if no custom ports specified then test the default ones
		if len(customport.Ports) == 0 {
			for _, method := range scanopts.Methods {
				wg.Add()
				go func(target, method string) {
					defer wg.Done()
					r := analyze(hp, protocol, target, 0, method, scanopts)
					output <- r
					if scanopts.TLSProbe && r.TLSData != nil {
						scanopts.TLSProbe = false
						for _, tt := range r.TLSData.DNSNames {
							process(tt, wg, hp, protocol, scanopts, output)
						}
						for _, tt := range r.TLSData.CommonName {
							process(tt, wg, hp, protocol, scanopts, output)
						}
					}
					if scanopts.CSPProbe && r.CSPData != nil {
						scanopts.CSPProbe = false
						for _, tt := range r.CSPData.Domains {
							process(tt, wg, hp, protocol, scanopts, output)
						}
					}
				}(target, method)
			}
		}

		// the host name shouldn't have any semicolon - in case remove the port
		semicolonPosition := strings.LastIndex(target, ":")
		if semicolonPosition > 0 {
			target = target[:semicolonPosition]
		}

		for port := range customport.Ports {
			for _, method := range scanopts.Methods {
				wg.Add()
				go func(port int, method string) {
					defer wg.Done()
					r := analyze(hp, protocol, target, port, method, scanopts)
					output <- r
					if scanopts.TLSProbe && r.TLSData != nil {
						scanopts.TLSProbe = false
						for _, tt := range r.TLSData.DNSNames {
							process(tt, wg, hp, protocol, scanopts, output)
						}
						for _, tt := range r.TLSData.CommonName {
							process(tt, wg, hp, protocol, scanopts, output)
						}
					}
				}(port, method)
			}
		}
	}
}

// returns all the targets within a cidr range or the single target
func targets(target string) chan string {
	results := make(chan string)
	go func() {
		defer close(results)

		// A valid target does not contain:
		// *
		// spaces
		if strings.ContainsAny(target, " *") {
			return
		}

		// test if the target is a cidr
		if iputils.IsCidr(target) {
			cidrIps, err := mapcidr.IPAddresses(target)
			if err != nil {
				return
			}
			for _, ip := range cidrIps {
				results <- ip
			}
		} else {
			results <- target
		}
	}()
	return results
}

type scanOptions struct {
	Methods            []string
	StoreResponseDir   string
	RequestURI         string
	RequestBody        string
	VHost              bool
	ExtractTitle       bool
	StatusCode         bool
	Location           bool
	ContentLength      bool
	StoreResponse      bool
	OutputServerHeader bool
	OutputWebSocket    bool
	NoColor            bool
	OutputMethod       bool
	ResponseInStdout   bool
	TLSProbe           bool
	CSPProbe           bool
	OutputContentType  bool
	Unsafe             bool
	Pipeline           bool
	HTTP2Probe         bool
	OutputIP           bool
	OutputCName        bool
	OutputCDN          bool
	OutputResponseTime bool
}

func analyze(hp *runner.HTTPX, protocol, domain string, port int, method string, scanopts *scanOptions) Result {
	retried := false
retry:
	URL := fmt.Sprintf("%s://%s", protocol, domain)
	if port > 0 {
		URL = fmt.Sprintf("%s://%s:%d", protocol, domain, port)
	}

	if !scanopts.Unsafe {
		URL += scanopts.RequestURI
	}

	req, err := hp.NewRequest(method, URL)
	if err != nil {
		return Result{URL: URL, err: err}
	}

	hp.SetCustomHeaders(req, hp.CustomHeaders)
	if scanopts.RequestBody != "" {
		req.ContentLength = int64(len(scanopts.RequestBody))
		req.Body = ioutil.NopCloser(strings.NewReader(scanopts.RequestBody))
	}

	resp, err := hp.Do(req)
	if err != nil {
		if !retried {
			if protocol == runner.HTTPS {
				protocol = runner.HTTP
			} else {
				protocol = runner.HTTPS
			}
			retried = true
			goto retry
		}
		return Result{URL: URL, err: err}
	}

	var fullURL string

	if resp.StatusCode >= 0 {
		if port > 0 {
			fullURL = fmt.Sprintf("%s://%s:%d%s", protocol, domain, port, scanopts.RequestURI)
		} else {
			fullURL = fmt.Sprintf("%s://%s%s", protocol, domain, scanopts.RequestURI)
		}
	}

	builder := &strings.Builder{}

	builder.WriteString(fullURL)

	if scanopts.StatusCode {
		builder.WriteString(" [")
		if !scanopts.NoColor {
			// Color the status code based on its value
			switch {
			case resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices:
				builder.WriteString(aurora.Green(strconv.Itoa(resp.StatusCode)).String())
			case resp.StatusCode >= http.StatusMultipleChoices && resp.StatusCode < http.StatusBadRequest:
				builder.WriteString(aurora.Yellow(strconv.Itoa(resp.StatusCode)).String())
			case resp.StatusCode >= http.StatusBadRequest && resp.StatusCode < http.StatusInternalServerError:
				builder.WriteString(aurora.Red(strconv.Itoa(resp.StatusCode)).String())
			case resp.StatusCode > http.StatusInternalServerError:
				builder.WriteString(aurora.Bold(aurora.Yellow(strconv.Itoa(resp.StatusCode))).String())
			}
		} else {
			builder.WriteString(strconv.Itoa(resp.StatusCode))
		}
		builder.WriteRune(']')
	}

	if scanopts.Location {
		builder.WriteString(" [")
		if !scanopts.NoColor {
			builder.WriteString(aurora.Magenta(resp.GetHeaderPart("Location", ";")).String())
		} else {
			builder.WriteString(resp.GetHeaderPart("Location", ";"))
		}
		builder.WriteRune(']')
	}

	if scanopts.OutputMethod {
		builder.WriteString(" [")
		if !scanopts.NoColor {
			builder.WriteString(aurora.Magenta(method).String())
		} else {
			builder.WriteString(method)
		}
		builder.WriteRune(']')
	}

	if scanopts.ContentLength {
		builder.WriteString(" [")
		if !scanopts.NoColor {
			builder.WriteString(aurora.Magenta(strconv.Itoa(resp.ContentLength)).String())
		} else {
			builder.WriteString(strconv.Itoa(resp.ContentLength))
		}
		builder.WriteRune(']')
	}

	if scanopts.OutputContentType {
		builder.WriteString(" [")
		if !scanopts.NoColor {
			builder.WriteString(aurora.Magenta(resp.GetHeaderPart("Content-Type", ";")).String())
		} else {
			builder.WriteString(resp.GetHeaderPart("Content-Type", ";"))
		}
		builder.WriteRune(']')
	}

	title := runner.ExtractTitle(resp)
	if scanopts.ExtractTitle {
		builder.WriteString(" [")
		if !scanopts.NoColor {
			builder.WriteString(aurora.Cyan(title).String())
		} else {
			builder.WriteString(title)
		}
		builder.WriteRune(']')
	}

	serverHeader := resp.GetHeader("Server")
	if scanopts.OutputServerHeader {
		builder.WriteString(fmt.Sprintf(" [%s]", serverHeader))
	}

	var serverResponseRaw = ""
	if scanopts.ResponseInStdout {
		serverResponseRaw = resp.Raw
	}

	// check for virtual host
	isvhost := false
	if scanopts.VHost {
		isvhost, _ = hp.IsVirtualHost(req)
		if isvhost {
			builder.WriteString(" [vhost]")
		}
	}

	// web socket
	isWebSocket := resp.StatusCode == 101
	if scanopts.OutputWebSocket && isWebSocket {
		builder.WriteString(" [websocket]")
	}

	pipeline := false
	if scanopts.Pipeline {
		pipeline = hp.SupportPipeline(protocol, method, domain, port)
		if pipeline {
			builder.WriteString(" [pipeline]")
		}
	}

	var http2 bool
	// if requested probes for http2
	if scanopts.HTTP2Probe {
		http2 = hp.SupportHTTP2(protocol, method, URL)
		if http2 {
			builder.WriteString(" [http2]")
		}
	}

	ip := cache.GetDialedIP(domain)
	if scanopts.OutputIP {
		builder.WriteString(fmt.Sprintf(" [%s]", ip))
	}

	var (
		ips    []string
		cnames []string
	)
	dnsData, err := cache.GetDNSData(domain)
	if dnsData != nil && err == nil {
		ips = dnsData.IPs
		cnames = dnsData.CNAMEs
	} else {
		ips = append(ips, ip)
	}

	if scanopts.OutputCName && len(cnames) > 0 {
		// Print only the first CNAME (full list in json)
		builder.WriteString(fmt.Sprintf(" [%s]", cnames[0]))
	}

	isCDN := hp.CdnCheck(ip)
	if scanopts.OutputCDN && isCDN {
		builder.WriteString(" [cdn]")
	}

	if scanopts.OutputResponseTime {
		builder.WriteString(fmt.Sprintf(" [%s]", resp.Duration))
	}

	// store responses in directory
	if scanopts.StoreResponse {
		domainFile := fmt.Sprintf("%s%s", domain, scanopts.RequestURI)
		if port > 0 {
			domainFile = fmt.Sprintf("%s.%d%s", domain, port, scanopts.RequestURI)
		}
		// On various OS the file max file name length is 255 - https://serverfault.com/questions/9546/filename-length-limits-on-linux
		// Truncating length at 255
		if len(domainFile) >= maxFileNameLenght {
			// leaving last 4 bytes free to append ".txt"
			domainFile = domainFile[:maxFileNameLenght-1]
		}

		domainFile = strings.ReplaceAll(domainFile, "/", "_") + ".txt"
		responsePath := path.Join(scanopts.StoreResponseDir, domainFile)
		err := ioutil.WriteFile(responsePath, []byte(resp.Raw), 0644)
		if err != nil {
			gologger.Warningf("Could not write response, at path '%s', to disc.", responsePath)
		}
	}

	return Result{
		raw:           resp.Raw,
		URL:           fullURL,
		ContentLength: resp.ContentLength,
		StatusCode:    resp.StatusCode,
		Location:      resp.GetHeaderPart("Location", ";"),
		ContentType:   resp.GetHeaderPart("Content-Type", ";"),
		Title:         title,
		str:           builder.String(),
		VHost:         isvhost,
		WebServer:     serverHeader,
		Response:      serverResponseRaw,
		WebSocket:     isWebSocket,
		TLSData:       resp.TLSData,
		CSPData:       resp.CSPData,
		Pipeline:      pipeline,
		HTTP2:         http2,
		Method:        method,
		IP:            ip,
		IPs:           ips,
		CNAMEs:        cnames,
		CDN:           isCDN,
		Duration:      resp.Duration,
	}
}

// Result of a scan
type Result struct {
	IPs           []string `json:"ips"`
	CNAMEs        []string `json:"cnames,omitempty"`
	raw           string
	URL           string `json:"url"`
	Location      string `json:"location"`
	Title         string `json:"title"`
	str           string
	err           error
	WebServer     string          `json:"webserver"`
	Response      string          `json:"serverResponse,omitempty"`
	ContentType   string          `json:"content-type,omitempty"`
	Method        string          `json:"method"`
	IP            string          `json:"ip"`
	ContentLength int             `json:"content-length"`
	StatusCode    int             `json:"status-code"`
	TLSData       *runner.TLSData `json:"tls,omitempty"`
	CSPData       *runner.CSPData `json:"csp,omitempty"`
	VHost         bool            `json:"vhost"`
	WebSocket     bool            `json:"websocket,omitempty"`
	Pipeline      bool            `json:"pipeline,omitempty"`
	HTTP2         bool            `json:"http2"`
	CDN           bool            `json:"cdn"`
	Duration      time.Duration   `json:"duration"`
}

// JSON the result
func (r *Result) JSON() string {
	if js, err := json.Marshal(r); err == nil {
		return string(js)
	}

	return ""
}
