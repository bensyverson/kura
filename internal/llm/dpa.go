package llm

// DPAConfig records which LLM providers the controller has a data
// processing agreement on file for. It is a startup configuration value,
// not a per-request one: the gateway checks it once, at construction.
//
// The check is deliberately a hard gate. A provider with no DPA on file
// is a provider Kura will not send data to, so NewGateway refuses to
// build a gateway for it.
type DPAConfig struct {
	onFile map[string]bool
}

// NewDPAConfig returns an empty DPAConfig — no provider has a DPA on file
// until one is attested.
func NewDPAConfig() *DPAConfig {
	return &DPAConfig{onFile: make(map[string]bool)}
}

// Attest records that the controller's DPA is on file for provider.
func (c *DPAConfig) Attest(provider string) {
	c.onFile[provider] = true
}

// OnFile reports whether the controller's DPA is on file for provider.
func (c *DPAConfig) OnFile(provider string) bool {
	return c.onFile[provider]
}
