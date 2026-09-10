package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// IncidentTelemetry strictly uses typed enum and numeric fields (Section 3).
// Arbitrary client text strings are rejected at ingress to eliminate Prompt Injection.
type IncidentTelemetry struct {
	IncidentID             string `json:"incident_id"`
	SignatureValid         bool   `json:"signature_valid"`
	NonceReplayed          bool   `json:"nonce_replayed"`
	SeqNumForkDetected     bool   `json:"seq_num_fork_detected"`
	SupersededPoPUsed      bool   `json:"superseded_pop_used"`
	HoneypotDecoyTriggered bool   `json:"honeypot_decoy_triggered"`
	TimeDeltaMs            int64  `json:"time_delta_ms"`
	RequestRatePerMin      int    `json:"request_rate_per_min"`
	IPReputationScore      int    `json:"ip_reputation_score"`
	OSBuildNumber          uint32 `json:"os_build_number"` // Numeric only
	TPMSpecFamily          uint16 `json:"tpm_spec_family"` // Numeric only (0x0200 for TPM 2.0)
	TimestampUnix          int64  `json:"timestamp_unix"`
}

type OllamaRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
}

type OllamaResponse struct {
	Response string `json:"response"`
}

type AISentinel struct {
	ollamaURL string
	modelName string
	client    *http.Client
}

func NewAISentinel(ollamaURL, modelName string) *AISentinel {
	if ollamaURL == "" {
		ollamaURL = "http://127.0.0.1:11434"
	}
	if modelName == "" {
		modelName = "llama3:latest"
	}
	return &AISentinel{
		ollamaURL: ollamaURL,
		modelName: modelName,
		client:    &http.Client{Timeout: 10 * time.Second},
	}
}

// AnalyzePostMortem submits strictly sanitized typed metrics to local Ollama.
// The model has zero automated authority: it only outputs post-mortem summaries for admins.
func (s *AISentinel) AnalyzePostMortem(ctx context.Context, telemetry IncidentTelemetry) (string, error) {
	metricsJSON, err := json.MarshalIndent(telemetry, "", "  ")
	if err != nil {
		return "", err
	}

	prompt := fmt.Sprintf(
		"You are a defensive telemetry analyst. Review the following structured hardware/licensing incident metrics.\n"+
			"Strict constraints: Evaluate attack patterns (clone, debugger, replay) without executable code.\n\n"+
			"Incident Metrics:\n%s\n\nProvide a 3-bullet concise post-mortem executive summary.",
		string(metricsJSON),
	)

	reqBody := OllamaRequest{
		Model:  s.modelName,
		Prompt: prompt,
		Stream: false,
	}

	rawJSON, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	endpoint := s.ollamaURL + "/api/generate"
	httpReq, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(rawJSON))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(httpReq)
	if err != nil {
		// Fallback diagnostic summary if Ollama instance is currently unreachable
		return fmt.Sprintf("[Offline Fallback Analysis] Incident %s: Clone=%v, DecoyHoneypot=%v, SeqFork=%v",
			telemetry.IncidentID, telemetry.SupersededPoPUsed, telemetry.HoneypotDecoyTriggered, telemetry.SeqNumForkDetected), nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ollama returned status %d", resp.StatusCode)
	}

	var ollamaResp OllamaResponse
	if err := json.NewDecoder(resp.Body).Decode(&ollamaResp); err != nil {
		return "", err
	}

	return ollamaResp.Response, nil
}
