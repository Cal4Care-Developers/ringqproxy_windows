package main

import (
	"fmt"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// Register manages SIP REGISTER towards the upstream RingQ PBX.
// It sends an initial REGISTER on Start() and re-registers every
// (expires - 30) seconds so the binding never lapses.
type Register struct {
	transport ClientTransport
	// registerServer: upstream PBX host:port, e.g. "pbx.ringq.ai:5060"
	registerServer string
	// from: the AOR being registered, e.g. sip:1001@pbx.ringq.ai
	from *NameAddr
	// contact: the address the PBX should send requests to (this proxy),
	// e.g. sip:1001@<proxy-lan-ip>:5060
	contact  string
	expires  int
	cseq     uint32
	callID   string
	stopped  int32
}

// NewRegister constructs a Register agent.
//
//   transport      - a ClientTransport already aimed at the PBX
//   registerServer - "pbx.ringq.ai:5060"
//   from           - parsed NameAddr of the AOR  (sip:1001@pbx.ringq.ai)
//   contact        - Contact URI string          (sip:1001@<proxy-lan-ip>:5060)
//   expires        - registration lifetime in seconds (e.g. 300)
func NewRegister(
	transport ClientTransport,
	registerServer string,
	from *NameAddr,
	contact string,
	expires int,
) *Register {
	callID, _ := CreateBranch() // reuse branch generator for a random string
	return &Register{
		transport:      transport,
		registerServer: registerServer,
		from:           from,
		contact:        contact,
		expires:        expires,
		cseq:           1,
		callID:         callID,
	}
}

// Start sends the first REGISTER and launches the refresh goroutine.
func (r *Register) Start() {
	if err := r.sendRegister(); err != nil {
		zap.L().Error("Initial REGISTER failed", zap.String("server", r.registerServer), zap.Error(err))
	}
	go r.refreshLoop()
}

// Stop cancels the refresh loop and sends a REGISTER with Expires: 0 to
// un-register the contact.
func (r *Register) Stop() {
	atomic.StoreInt32(&r.stopped, 1)
	_ = r.sendRegisterWithExpires(0)
}

// refreshLoop re-registers before the current registration expires.
func (r *Register) refreshLoop() {
	interval := r.expires - 30
	if interval < 30 {
		interval = 30
	}
	for {
		time.Sleep(time.Duration(interval) * time.Second)
		if atomic.LoadInt32(&r.stopped) != 0 {
			return
		}
		if err := r.sendRegister(); err != nil {
			zap.L().Error("REGISTER refresh failed", zap.String("server", r.registerServer), zap.Error(err))
		}
	}
}

func (r *Register) sendRegister() error {
	return r.sendRegisterWithExpires(r.expires)
}

func (r *Register) sendRegisterWithExpires(expires int) error {
	cseq := atomic.AddUint32(&r.cseq, 1)

	// Request-URI: sip:<registerServer>
	requestURI := fmt.Sprintf("sip:%s", r.registerServer)

	msg, err := NewRequest("REGISTER", requestURI, "SIP/2.0")
	if err != nil {
		return fmt.Errorf("build REGISTER request: %w", err)
	}

	// Via  - proxy's own address; branch is per-transaction
	branch, err := CreateBranch()
	if err != nil {
		return fmt.Errorf("create branch: %w", err)
	}
	// Extract proxy listen address from the contact URI (sip:user@host:port)
	proxyViaHost, proxyViaPort, parseErr := parseContactHostPort(r.contact)
	if parseErr != nil {
		return fmt.Errorf("sendRegisterWithExpires: %w", parseErr)
	}
	via := CreateViaParam("UDP", proxyViaHost, proxyViaPort)
	via.SetBranch(branch)
	viaHdr := NewVia()
	viaHdr.AddViaParam(via)
	msg.AddHeader("Via", viaHdr.String())

	// From / To  - same AOR (RFC 3261 --10.2)
	fromTag, _ := CreateTag()
	fromStr := fmt.Sprintf("%s;tag=%s", r.from.String(), fromTag)
	msg.AddHeader("From", fromStr)
	msg.AddHeader("To", r.from.String())

	// Call-ID
	msg.AddHeader("Call-ID", r.callID)

	// CSeq
	msg.AddHeader("CSeq", fmt.Sprintf("%d REGISTER", cseq))

	// Contact
	msg.AddHeader("Contact", fmt.Sprintf("<%s>", r.contact))

	// Expires
	msg.AddHeader("Expires", fmt.Sprintf("%d", expires))

	// Max-Forwards
	msg.AddHeader("Max-Forwards", "70")

	// Content-Length (no body)
	msg.AddHeader("Content-Length", "0")

	zap.L().Info("Sending REGISTER",
		zap.String("server", r.registerServer),
		zap.String("contact", r.contact),
		zap.Int("expires", expires),
		zap.Uint32("cseq", cseq),
	)

	return r.transport.Send(msg)
}

// parseContactHostPort extracts host and port from a Contact URI string,
// e.g. "sip:user@<proxy-lan-ip>:5060" or "sip:<proxy-lan-ip>:5060".
// Returns an error if the URI cannot be parsed; the caller should abort the
// REGISTER rather than send to a wrong address.
func parseContactHostPort(contact string) (host string, port int, err error) {
	sipURI, parseErr := ParseSipURI(contact)
	if parseErr != nil {
		return "", 0, fmt.Errorf("parseContactHostPort: invalid Contact URI %q: %w", contact, parseErr)
	}
	return sipURI.Host, sipURI.GetPort(), nil
}