package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/l3montree-dev/traefik-crowdsec-bouncer/config"
	"github.com/l3montree-dev/traefik-crowdsec-bouncer/model"
	"github.com/rs/zerolog/log"
)

const (
	realIpHeader         = "X-Real-Ip"
	forwardHeader        = "X-Forwarded-For"
	crowdsecAuthHeader   = "X-Api-Key"
	crowdsecBouncerRoute = "v1/decisions"
	healthCheckIp        = "127.0.0.1"
)

var crowdsecBouncerApiKey = config.RequiredEnv("CROWDSEC_BOUNCER_API_KEY")
var crowdsecBouncerHost = config.RequiredEnv("CROWDSEC_AGENT_HOST")
var crowdsecBouncerScheme = config.OptionalEnv("CROWDSEC_BOUNCER_SCHEME", "http")
var crowdsecBanResponseCode, _ = strconv.Atoi(config.OptionalEnv("CROWDSEC_BOUNCER_BAN_RESPONSE_CODE", "403")) // Validated via ValidateEnv()
var crowdsecBanResponseMsg = config.OptionalEnv("CROWDSEC_BOUNCER_BAN_RESPONSE_MSG", "Forbidden")
var (
	ipProcessed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "crowdsec_traefik_bouncer_processed_ip_total",
		Help: "The total number of processed IP",
	})
)

var client = &http.Client{
	Transport: &http.Transport{
		MaxIdleConns:    10,
		IdleConnTimeout: 30 * time.Second,
	},
	Timeout: 5 * time.Second,
}

/*
*
Call Crowdsec local IP and with realIP and return true if IP does NOT have a ban decisions.
*/
func isIpAuthorized(parentCTX context.Context, clientIP string) (bool, error) {
	// Generating crowdsec API request
	decisionUrl := url.URL{
		Scheme:   crowdsecBouncerScheme,
		Host:     crowdsecBouncerHost,
		Path:     crowdsecBouncerRoute,
		RawQuery: fmt.Sprintf("type=ban&ip=%s", clientIP),
	}
	ctx, cancel := context.WithTimeout(parentCTX, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, decisionUrl.String(), nil)
	if err != nil {
		return false, err
	}
	req.Header.Add(crowdsecAuthHeader, crowdsecBouncerApiKey)
	slog.Debug("request crowdsecs decision local api", "url", decisionUrl.String())

	// Calling crowdsec API
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	if resp.StatusCode == http.StatusForbidden {
		return false, err
	}
	defer resp.Body.Close()
	reqBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	if bytes.Equal(reqBody, []byte("null")) {
		slog.Info("no decision for IP. Accepting", "ip", clientIP)
		return true, nil
	}

	slog.Debug("found Crowdsec's decision(s), evaluating ...")
	var decisions []model.Decision
	err = json.Unmarshal(reqBody, &decisions)
	if err != nil {
		return false, errors.Wrap(err, string(reqBody))
	}

	// Authorization logic
	return len(decisions) == 0, nil
}

func readUserIP(r *http.Request) string {
	IPAddress := r.Header.Get(realIpHeader)
	if IPAddress == "" {
		IPAddress = r.Header.Get(forwardHeader)
	}
	if IPAddress == "" {
		IPAddress, _, _ = net.SplitHostPort(r.RemoteAddr)
	}

	return IPAddress
}

/*
Main route used by Traefik to verify authorization for a request
*/
func ForwardAuth(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ipProcessed.Inc()
	clientIP := readUserIP(r)
	slog.Debug("handling forwardAuth request", "ip", clientIP)
	// Getting and verifying ip using ClientIP function
	isAuthorized, err := isIpAuthorized(r.Context(), clientIP)
	slog.Debug("handled request", "ip", clientIP, "isAuthorized", isAuthorized, "took", time.Since(start))
	if err != nil {
		slog.Warn("an error occured while checking IP", "err", err, "ip", clientIP)
		w.WriteHeader(crowdsecBanResponseCode)
		w.Write([]byte(crowdsecBanResponseMsg))
	} else if !isAuthorized {
		w.WriteHeader(crowdsecBanResponseCode)
		w.Write([]byte(crowdsecBanResponseMsg))

	} else {
		w.WriteHeader(http.StatusOK)
	}
}

/*
Route to check bouncer connectivity with Crowdsec agent. Mainly use for Kubernetes readiness probe
*/
func Healthz(w http.ResponseWriter, r *http.Request) {
	isHealthy, err := isIpAuthorized(r.Context(), healthCheckIp)
	if err != nil || !isHealthy {
		log.Warn().Err(err).Msgf("The health check did not pass. Check error if present and if the IP %q is authorized", healthCheckIp)
		w.WriteHeader(http.StatusForbidden)
	} else {
		w.WriteHeader(http.StatusOK)
	}
}

/*
Simple route responding pong to every request. Mainly use for Kubernetes liveliness probe
*/
func Ping(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("pong"))
}

func Metrics(w http.ResponseWriter, r *http.Request) {
	handler := promhttp.Handler()
	handler.ServeHTTP(w, r)
}
