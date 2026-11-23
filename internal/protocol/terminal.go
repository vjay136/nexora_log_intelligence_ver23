package protocol

// Terminal payloads are ephemeral authenticated control traffic, never parser
// assets, persisted commands, transcript storage or AI context.
type TerminalStatus struct {
	Supported          bool   `json:"supported"`
	Enabled            bool   `json:"enabled"`
	PrivilegeMode      string `json:"privilege_mode"`
	Generation         string `json:"generation"`
	AccessEpoch        string `json:"access_epoch,omitempty"`
	Reason             string `json:"reason,omitempty"`
	MaxSessions        int    `json:"max_sessions"`
	IdleTimeoutSeconds int    `json:"idle_timeout_seconds"`
	LifetimeSeconds    int    `json:"lifetime_seconds"`
}
type TerminalInput struct {
	Sequence uint64 `json:"sequence"`
	Data     []byte `json:"data"`
}
type TerminalSessionDirective struct {
	ID     string          `json:"id"`
	Cols   uint16          `json:"cols"`
	Rows   uint16          `json:"rows"`
	Close  bool            `json:"close"`
	After  uint64          `json:"after"`
	Inputs []TerminalInput `json:"inputs,omitempty"`
}
type TerminalSessionUpdate struct {
	ID         string `json:"id"`
	Status     string `json:"status"`
	Reason     string `json:"reason,omitempty"`
	Start      uint64 `json:"start"`
	Next       uint64 `json:"next"`
	Data       []byte `json:"data,omitempty"`
	Truncated  bool   `json:"truncated"`
	AckedInput uint64 `json:"acked_input"`
	ExitCode   int    `json:"exit_code"`
}
type TerminalExchangeRequest struct {
	NodeID   string                  `json:"node_id"`
	Terminal TerminalStatus          `json:"terminal"`
	Sessions []TerminalSessionUpdate `json:"sessions"`
}
type TerminalExchangeResponse struct {
	Sessions    []TerminalSessionDirective `json:"sessions"`
	PollAfterMS int                        `json:"poll_after_ms"`
}
