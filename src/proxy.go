package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"time"

	"go.uber.org/zap"
)

// tunnelHTTPClient is shared by bindDevice, heartbeatLoop, and
// reportTunnelStatus for all PBX tunnel-API calls.
//
// http.Post()/http.DefaultClient use http.DefaultTransport, whose
// TLSHandshakeTimeout is hardcoded to 10s. On a fresh/rebuilt Windows
// binary, endpoint security (e.g. Windows Defender cloud-delivered
// protection) can add several seconds of latency to the *first* outbound
// connection from an unrecognized executable, which is enough to blow
// past that 10s default and surface as "TLS handshake timeout" even
// though the network path itself is fine. 20s gives real headroom without
// masking a genuinely dead PBX for long.
//
// HTTP/2 is explicitly disabled below. Go's http.Transport offers h2 via
// ALPN by default on every HTTPS connection; a working curl test against
// the same PBX endpoint only offered http/1.1 (no h2 support in that curl
// build) and connected instantly, while the Go client -- offering h2 --
// hung after the handshake with no response ("wsarecv" timeout). This
// points at something on the network path (firewall/AV inspection)
// mishandling HTTP/2 framing specifically. Forcing http/1.1 avoids it.
var tunnelHTTPClient = &http.Client{
	Timeout: 20 * time.Second,
	Transport: &http.Transport{
		TLSHandshakeTimeout:   20 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		ForceAttemptHTTP2:     false,
		// Empty (non-nil) map disables HTTP/2 entirely, forcing http/1.1
		// even if the server advertises h2 support via ALPN.
		TLSNextProto: make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
		// Confirmed fix (2026-07-02): Go's default TLS 1.3 ClientHello is
		// getting silently dropped somewhere on certain office Wi-Fi/router
		// paths (reproduced with a minimal standalone Go program with zero
		// proxy code -- hung every time at the 10s TLSHandshakeTimeout).
		// Forcing TLS 1.2 shrinks the ClientHello (drops the TLS 1.3
		// key_share extension) and connects in ~3s reliably. curl/Schannel
		// were unaffected because they use the OS TLS stack, not Go's.
		TLSClientConfig: &tls.Config{
			MaxVersion: tls.VersionTLS12,
		},
	},
}

type ProxyItem struct {
	sync.Mutex
	transports []ServerTransport
	viaConfig  *ViaConfig
	backend    *RoundRobinBackend
	msgHandler MessageHandler
}

// MyName is a structure to hold the name and patterns for matching SIP messages
type MyName struct {
	names    []string
	patterns []*regexp.Regexp
}

func NewMyName(name string) *MyName {
	tmp := strings.Split(name, ",")
	myName := &MyName{names: make([]string, 0), patterns: make([]*regexp.Regexp, 0)}

	for _, t := range tmp {
		s := strings.TrimSpace(t)
		myName.names = append(myName.names, s)
		p, err := regexp.Compile(s)
		if err == nil {
			myName.patterns = append(myName.patterns, p)
		}
	}
	return myName
}

func (p *MyName) matchAbsoluteURI(absoluteURI string) bool {
	for _, name := range p.names {
		if absoluteURI == name {
			return true
		}
	}

	for _, pattern := range p.patterns {
		if pattern.MatchString(absoluteURI) {
			return true
		}
	}
	return false

}

func (p *MyName) matchSIPURI(user string, hostName string) bool {
	for _, name := range p.names {
		pos := strings.Index(name, "@")
		if pos == -1 {
			if hostName == name {
				return true
			}
		} else {
			if hostName == name[pos+1:] && user == name[0:pos] {
				return true
			}
		}
	}

	userHost := fmt.Sprintf("%s@%s", user, hostName)
	for _, pattern := range p.patterns {
		if pattern.MatchString(userHost) {
			return true
		}

	}
	return false

}

func (p *MyName) isMyMessage(msg *Message) bool {
	requestURI, err := msg.GetRequestURI()
	if err != nil {
		zap.L().Error("Fail to find the requestURI in message", zap.String("message", msg.String()))
		return false
	}
	absoluteURI, err := requestURI.GetAbsoluteURI()
	if err == nil {
		if p.matchAbsoluteURI(absoluteURI.String()) {
			return true
		}
	}

	sipUri, err := requestURI.GetSIPURI()
	if err == nil {
		if msg.ReceivedFrom != nil && sipUri.Host == msg.ReceivedFrom.GetAddress() && sipUri.GetPort() == msg.ReceivedFrom.GetPort() {
			return true
		}
		if p.matchSIPURI(sipUri.User, sipUri.Host) {
			return true
		}
	}
	return false

}

type UserRegistry struct {
	sync.RWMutex
	m map[string]string
}

func NewUserRegistry() *UserRegistry { return &UserRegistry{m: make(map[string]string)} }
func (r *UserRegistry) Set(u, a string) {
	r.Lock()
	r.m[u] = a
	r.Unlock()
}
func (r *UserRegistry) Get(u string) (string, bool) {
	r.RLock()
	defer r.RUnlock()
	v, ok := r.m[u]
	return v, ok
}
func (r *UserRegistry) Delete(u string) { r.Lock(); delete(r.m, u); r.Unlock() }

type Proxy struct {
	myName                 *MyName
	listenConfigs          []ListenConfig
	receivedSupport        bool
	keepNextHopRoute       bool
	preConfigRoute         *PreConfigRoute
	resolver               *PreConfigHostResolver
	items                  []*ProxyItem
	clientTransMgr         *ClientTransportMgr
	selfLearnRoute         *SelfLearnRoute
	mustRecordRoute        bool
	msgChannel             chan *RawMessage
	connAcceptedChannel    chan net.Conn
	sessionBackends        SessionBasedBackend
	clientTransportFactory *ClientTransportFactory
	userRegistry           *UserRegistry
	// apiBaseURL is the base URL of the RingQ PBX REST API.
	// Loaded from pbx-api-url in YAML (e.g. "https://customer.ringq.ai:8443").
	// The proxy appends /tunnel/bind and /tunnel/heartbeat to this.
	// Defaults to "https://<pbxDomain>" when not set.
	apiBaseURL string
	// authKey is the tunnel authentication key from auth-key in YAML.
	// It is injected into every SIP request forwarded from the proxy to the
	// PBX (via X-RingQ-Auth header) so the PBX can authenticate the NX Device
	// against the tunnel_config table.  Empty = no auth header injected.
	authKey string
	// tunnelBound is the SIP gate flag. True = tunnel authenticated, traffic flows.
	// False = tunnel not yet bound or auth rejected; phones receive 503.
	// One atomic read per request (~1 ns) -- negligible overhead.
	// Set by bindDevice() on success; cleared on explicit auth rejection.
	// Network errors (PBX temporarily unreachable) leave it unchanged.
	tunnelBound int32 // atomic: 0=not bound, 1=bound; use atomic.LoadInt32/StoreInt32
	// deviceID uniquely identifies this NX Device installation.
	// Sourced from /etc/machine-id via device-id in YAML.
	// Sent as X-Device-ID on every outbound SIP request to the PBX.
	deviceID string
	// pbxDomain is the RingQ PBX SIP domain loaded from pbx-domain in YAML.
	// REGISTER/INVITE To, From, and Request-URI headers are rewritten to this
	// domain before forwarding upstream so the PBX can resolve the correct
	// tenant, dialplan context, and auth realm.
	pbxDomain string
	// phonesDomain is the SIP server address that LAN phones are provisioned
	// with (e.g. the proxy's LAN IP). Loaded from phones-domain in YAML; if
	// omitted, defaults to listens[0].address. Only headers whose host is
	// exactly this value are rewritten to pbxDomain.
	phonesDomain string
}




// validSIPMethods is the set of standard SIP methods (RFC 3261 and common
// extensions). Used to reject malformed/truncated requests - see the
// "Discard requests with a garbage/unknown method" check in handleMessage.
var validSIPMethods = map[string]bool{
	"INVITE":    true,
	"ACK":       true,
	"BYE":       true,
	"CANCEL":    true,
	"OPTIONS":   true,
	"REGISTER":  true,
	"PRACK":     true,
	"SUBSCRIBE": true,
	"NOTIFY":    true,
	"PUBLISH":   true,
	"INFO":      true,
	"REFER":     true,
	"MESSAGE":   true,
	"UPDATE":    true,
}

func NewProxy(name string,
	dialogExpire int64,
	listenConfigs []ListenConfig,
	keepNextHopRoute bool,
	preConfigRoute *PreConfigRoute,
	resolver *PreConfigHostResolver,
	selfLearnRoute *SelfLearnRoute,
	receivedSupport bool,
	mustRecordRoute bool,
	redisSessionStore *RedisSessionStore,
	pbxDomain string,
	phonesDomain string,
	authKey string,
	deviceID string,
	apiBaseURL string) *Proxy {

	proxy := &Proxy{myName: NewMyName(name),
		listenConfigs:          listenConfigs,
		receivedSupport:        receivedSupport,
		keepNextHopRoute:       keepNextHopRoute,
		preConfigRoute:         preConfigRoute,
		resolver:               resolver,
		items:                  make([]*ProxyItem, 0),
		clientTransMgr:         nil,
		selfLearnRoute:         selfLearnRoute,
		mustRecordRoute:        mustRecordRoute,
		msgChannel:             make(chan *RawMessage, 10000),
		connAcceptedChannel:    make(chan net.Conn),
		sessionBackends:        nil,
		clientTransportFactory: NewClientTransportFactory(resolver),
		userRegistry:           NewUserRegistry(),
		pbxDomain:              pbxDomain,
		phonesDomain:           phonesDomain,
		authKey:                authKey,
		deviceID:               deviceID,
		apiBaseURL:             apiBaseURL}

	for _, listenConf := range listenConfigs {
		item, err := NewProxyItem(listenConf, receivedSupport, proxy, selfLearnRoute, proxy)
		if err == nil {
			proxy.items = append(proxy.items, item)
		}
	}

	connectionEstablished := func(conn net.Conn) {
		serverTransport := NewTCPServerTransportWithConn(conn, proxy.receivedSupport, selfLearnRoute, nil)
		serverTransport.Start(proxy)
	}

	proxy.clientTransMgr = NewClientTransportMgr(proxy.clientTransportFactory, selfLearnRoute, connectionEstablished)

	if redisSessionStore != nil {
		findBackendByAddr := func(backendAddr string) (Backend, error) {
			// find the backend by address
			for _, item := range proxy.items {
				backend, err := item.findBackendByAddr(backendAddr)
				if err == nil {
					zap.L().Info("succeed to find backend by address get from redis", zap.String("backendAddr", backendAddr))
					return backend, nil
				}
			}
			return nil, fmt.Errorf("fail to find backend by address %s", backendAddr)
		}
		zap.L().Info("use redis session store for dialog and transaction", zap.Any("redisAddr", redisSessionStore), zap.Int64("dialogExpire", dialogExpire))
		sessionBackends := []SessionBasedBackend{NewLocalSessionBasedBackend(dialogExpire), NewMasterSlaveRedisSessionBasedBackend(*redisSessionStore, dialogExpire, findBackendByAddr)}
		proxy.sessionBackends = NewCompositeSessionBasedBackend(sessionBackends)
	} else {
		zap.L().Info("use local session store for dialog and transaction")
		proxy.sessionBackends = NewLocalSessionBasedBackend(dialogExpire)
	}

	go proxy.receiveAndProcessMessage()
	return proxy
}

func (p *Proxy) Start() error {
	for _, item := range p.items {
		err := item.Start()
		if err != nil {
			return err
		}
	}
	// Tunnel gate: open immediately if no auth is configured (open/dev mode).
	if p.authKey == "" || p.deviceID == "" {
		atomic.StoreInt32(&p.tunnelBound, 1)
	}
	// Bind this NX Device to the PBX tunnel record (blocks until success).
	// Runs in a goroutine so it doesn't block the caller; SIP listeners are
	// already up but the PBX won't accept messages until device_id is bound.
	go func() {
		p.bindDevice()
		go p.heartbeatLoop()
	}()
	return nil
}

func (p *Proxy) HandleRawMessage(msg *RawMessage) {
	p.msgChannel <- msg
}

// ConnectionAccepted implement ConnectionAcceptedListener interface
func (p *Proxy) ConnectionAccepted(conn net.Conn) {
	p.connAcceptedChannel <- conn
}

func (p *Proxy) receiveAndProcessMessage() {
	for {
		select {
		case rawMsg := <-p.msgChannel:
			msg, err := p.handleRawMessage(rawMsg)
			if err == nil {
				p.handleMessage(rawMsg.From.GetProtocol(), msg, rawMsg.Backend, rawMsg.Via)
				p.handleSession(msg)
			}

		case conn := <-p.connAcceptedChannel:
			host, port, err := net.SplitHostPort(conn.RemoteAddr().String())
			if err == nil {
				port_i, err := strconv.Atoi(port)
				if err == nil {
					trans, err := p.clientTransMgr.GetTransport("tcp", host, port_i, "")
					if err == nil {
						trans.primary, _ = NewTCPClientTransportWithConn(conn)
					}
				}
			}
		}
	}
}

func (p *Proxy) handleRawMessage(rawMessage *RawMessage) (*Message, error) {
	msg := rawMessage.Message
	msg.ReceivedFrom = rawMessage.From
	//if msg.IsRequest() && !p.isBackendAddr(rawMessage.PeerAddr) {
	if msg.IsRequest() {
		p.selfLearnRoute.AddRoute(rawMessage.PeerAddr, rawMessage.From)
		msg.ForEachViaParam(func(viaParam *ViaParam) {
			p.selfLearnRoute.AddRoute(viaParam.Host, rawMessage.From)
		})
	}
	// set the received parameters
	if msg.IsRequest() && rawMessage.ReceivedSupport {
		msg.SetReceived(rawMessage.PeerAddr, rawMessage.PeerPort)
	}
	if msg.IsRequest() && rawMessage.TcpConn != nil {
		host, port, _, err := p.getNextReponseHop(msg)
		if strings.HasPrefix(host, "[") {
			host = host[1 : len(host)-1]
		}
		if err != nil {
			zap.L().Error("fail to get host/port of the next response", zap.String("error", err.Error()))
		}
		zap.L().Info("receive a message from tcp", zap.String("host", host), zap.Int("port", port))
		if err == nil {
			// create a transport for transaction in tcp connection
			transId, err := msg.GetClientTransaction()
			if err == nil {
				trans, err := p.clientTransMgr.GetTransport("tcp", host, port, transId)
				if err == nil {
					trans.primary, _ = NewTCPClientTransportWithConn(rawMessage.TcpConn)
				} else {
					zap.L().Error("fail to get tcp transport", zap.String("host", host), zap.Int("port", port), zap.String("transactionId", transId), zap.String("error", err.Error()))
				}
			} else {
				zap.L().Error("fail to get client transaction", zap.String("error", err.Error()))
			}
		}
	}
	// The proxy will inspect the URI in the topmost Route header
	// field value.  If it indicates this proxy, the proxy removes it
	// from the Route header field (this route node has been
	// reached).

	p.tryRemoveTopRoute(rawMessage)
	return msg, nil
}

func (p *Proxy) tryRemoveTopRoute(rawMessage *RawMessage) {
	msg := rawMessage.Message

	route, err := msg.GetRoute()
	if err != nil {
		return
	}
	routeParam, err := route.GetRouteParam(0)
	if err != nil {
		return
	}
	sipUri, err := routeParam.GetAddress().GetAddress().GetSIPURI()

	if err != nil {
		return
	}

	myAddr := rawMessage.From.GetAddress()
	myPort := rawMessage.From.GetPort()

	if sipUri.GetPort() == myPort && p.isSameAddress(sipUri.Host, myAddr) {
		zap.L().Info("remove top route item because the top item is my address", zap.String("route-param", routeParam.String()))
		msg.PopRoute()
	}
}

// isSameAddress check if the two addresses are the same
// if the two addresses are the same, return true, otherwise return false
func (p *Proxy) isSameAddress(addr1 string, addr2 string) bool {
	if addr1 == addr2 {
		return true
	}

	ips1, err := p.resolver.GetIps(addr1)
	if err != nil {
		return false
	}

	ips2, err := p.resolver.GetIps(addr2)

	if err != nil {
		return false
	}

	for _, ip1 := range ips1 {
		if slices.IndexFunc(ips2, func(ip2 string) bool {
			return ip2 == ip1
		}) != -1 {
			return true
		}
	}

	return false

}

func (p *Proxy) handleSession(msg *Message) {
	if !msg.IsResponse() {
		return
	}

	if sessionId, err := msg.GetSessionId(); err == nil {
		if backend, err := p.sessionBackends.GetBackend(sessionId); err == nil {
			addr := backend.GetAddress()

			if method, err := msg.GetMethod(); err == nil && method == "BYE" {
				p.sessionBackends.RemoveSession(sessionId)
				zap.L().Info("session is removed after getting a BYE message", zap.String("sessionId", sessionId), zap.String("backendAddr", addr))
			}
		}
	}

}

func (p *Proxy) handleMessage(protocol string, msg *Message, backend Backend, viaConfig *ViaConfig) {
	callId, _ := msg.GetCallID()
	if zap.L().Core().Enabled(zap.DebugLevel) {
		zap.L().Debug("Received a message", zap.String("localHost", msg.ReceivedFrom.GetAddress()), zap.Int("port", msg.ReceivedFrom.GetPort()), zap.String("message", msg.String()))
	} else {
		zap.L().Info("Received a message", zap.String("localHost", msg.ReceivedFrom.GetAddress()), zap.Int("port", msg.ReceivedFrom.GetPort()), zap.String("call-id", callId))
	}
	if msg.IsRequest() {
		// 0. Discard requests with a garbage/unknown method.
		//
		// Observed in production: small UDP packets (2-4 bytes), likely
		// stray retransmissions or keepalives from the Yealink phone,
		// occasionally get parsed with a truncated method such as "STER"
		// or "GISTER" (a corrupted "REGISTER"). Such a message is not
		// caught by the `method == "REGISTER"` checks elsewhere (since
		// "STER" != "REGISTER"), so it falls through to
		// routeToRegisteredPhone, which forwards it to the LAN phone as
		// if it were a legitimate inbound request. The phone correctly
		// replies "405 Method Not Allowed", and the cycle repeats every
		// ~13 seconds.
		//
		// Fix: validate the method against the RFC-defined SIP method set
		// before doing anything else. Anything else is dropped and logged.
		if method, mErr := msg.GetMethod(); mErr != nil || !validSIPMethods[method] {
			zap.L().Warn("Dropping request with invalid/unknown method",
				zap.String("method", method),
				zap.String("message", msg.String()))
			return
		}

		// 1. Learn user->LAN-phone mapping from every REGISTER's Contact.
		p.learnRegistration(msg)

		// 1b. Intercept REGISTER Expires:0 (deregistration) from LAN phones.
		//     Do NOT forward to the PBX. Instead, respond 200 OK locally.
		//
		//     Root cause of registration flapping:
		//       MicroSIP (Expires:300) and Client Win (short Expires) routinely
		//       send REGISTER Expires:0 just before re-registering. If forwarded:
		//         1. PBX removes the registration immediately.
		//         2. PBX sends an OPTIONS "goodbye" ping via UDP to
		//            43.225.164.198:5060. Fortigate drops it.
		//         3. 32-second timeout -> Ping-Status: Unreachable -> expired.
		//       The new REGISTER that follows re-creates the registration, but the
		//       gap is enough for the next options-ping to conclude Unreachable.
		//
		//     With this intercept:
		//       - PBX registration stays alive throughout the cycle.
		//       - learnRegistration() above already removed the user from the
		//         local LAN registry (so inbound calls during the brief gap get
		//         a correct 480 Temporarily Unavailable).
		//       - When the phone re-registers with Expires:N, the REGISTER is
		//         forwarded normally and the PBX renews the expiry.
		if mMethod, mErr := msg.GetMethod(); mErr == nil && mMethod == "REGISTER" &&
			msg.GetExpires(300) == 0 {
			p.respondOKToLocalDeregister(msg)
			return
		}

		// 2. Route inbound INVITE/OPTIONS from PBX to the LAN phone.
		//    Runs BEFORE getNextRequestHop to prevent the "default" route
		//    from looping the request back to PBX.
		//    REGISTER is excluded - it always goes upstream to PBX.
		if handled := p.routeToRegisteredPhone(msg, protocol); handled {
			return
		}

		// 3. Tunnel authentication gate.
		//    Reject phone->PBX traffic if the tunnel has not been authenticated.
		//    One atomic read (~1 ns) per request -- negligible overhead.
		//
		//    Already safe before this point:
		//      * REGISTER Expires:0 -> answered locally  (step 1b)
		//      * OPTIONS from PBX   -> answered locally  (step 2 / respondOKToOptions)
		//      * B-leg INVITE/etc.  -> delivered to phone (step 2 / routeToRegisteredPhone)
		//    Only phone->PBX messages (REGISTER Expires:N, INVITE, BYE ...) reach here.
		if atomic.LoadInt32(&p.tunnelBound) == 0 {
			p.rejectWithServiceUnavailable(msg)
			return
		}

		// 4. Normal outbound routing (phone -> PBX).
		host, port, transport, err := p.getNextRequestHop(msg)
		if err == nil {
			zap.L().Info("Get next hop for request", zap.String("host", host), zap.Int("port", port), zap.String("transport", transport))
			serverTrans, ok := p.selfLearnRoute.GetRoute(host, protocol)
			if !ok {
				// selfLearnRoute hasn't seen a message from PBX yet (e.g. the
				// proxy just restarted and the first INVITE from a LAN phone
				// arrived before PBX sent its first OPTIONS ping).
				//
				// Without this fallback addVia and addRecordRoute are both
				// skipped: the INVITE reaches PBX with no proxy Via and no
				// Record-Route. PBX sends 200 OK back through the proxy (the
				// NAT gateway NAT entry keeps the path alive), but without
				// Record-Route the calling phone (MicroSIP) tries to send ACK
				// directly to the Contact URI (PBX's external IP). If the
				// NAT gateway blocks direct SIP from LAN to internet the ACK is
				// lost, PBX retransmits 200 OK indefinitely, and the call is
				// stuck -- never answered from the caller's perspective.
				//
				// Fix: fall back to the proxy's own listener transport.
				// This produces:
				//   Via:          SIP/2.0/UDP <proxy-lan-ip>:5060;branch=...
				//   Record-Route: <sip:<proxy-lan-ip>:5060;lr>
				// Both MicroSIP (same LAN) and PBX (routed via gateway to
				// proxy LAN) can reach <proxy-lan-ip>:5060, so all
				// in-dialog requests (ACK, BYE) continue to flow through the
				// proxy correctly regardless of when PBX first sends a ping.
			outerFallback:
				for _, item := range p.items {
					for _, t := range item.transports {
						serverTrans = t
						ok = true
						zap.L().Info("selfLearnRoute miss -- using local listener as Via/RR fallback",
							zap.String("addr", t.GetAddress()), zap.Int("port", t.GetPort()))
						break outerFallback
					}
				}
			}
			// Capture the caller's original Via string BEFORE addVia prepends
			// the proxy's own Via. After addVia the caller's Via drops to
			// index 1; we need it now at index 0 for sendSynthetic100Trying.
			var callerViaStr string
			if via, vErr := msg.GetVia(); vErr == nil {
				if vp, vpErr := via.GetParam(0); vpErr == nil {
					callerViaStr = vp.String()
				}
			}

			if ok {
				p.addVia(msg, serverTrans)
				p.addRecordRoute(msg, serverTrans)

				// When forwarding upstream via TCP the Via transport MUST say
				// "TCP" so FreeSWITCH sends its 401/200 response back on the
				// same TCP connection (RFC 3261 section 18.2.2).
				//
				// Without this fix the Via says "UDP" (from the via config),
				// FS tries to send its response via new UDP to 43.225.164.198
				// :5060, the Fortigate has no inbound UDP VIP for that port so
				// it drops the packet, and registration never completes.
				if strings.EqualFold(transport, "tcp") {
					if via, vErr := msg.GetVia(); vErr == nil {
						if vp, vpErr := via.GetParam(0); vpErr == nil {
							vp.Transport = "TCP"
							zap.L().Info("Overrode proxy Via transport to TCP for upstream TCP forwarding",
								zap.String("viaHost", vp.Host),
								zap.Int("viaPort", vp.GetPort()))
						}
					}
				}
			}
			p.rewriteContactForUpstream(msg, viaConfig)
			p.rewriteDomainForUpstream(msg, viaConfig)
			// Inject tunnel auth headers so the PBX can authenticate this
			// NX Device against the tunnel_config table.
			p.addTunnelAuthHeaders(msg)

			p.sendRequest(host, port, transport, msg)

			// Immediately send a synthetic 100 Trying back to the INVITE
			// caller so PJSIP-based clients move from CALLING to PROCEEDING
			// state and can then send CANCEL when the user hangs up.
			p.sendSynthetic100Trying(msg, callerViaStr)
		} else if p.myName.isMyMessage(msg) {
			zap.L().Info("it is my request", zap.String("call-id", callId))
			p.rewriteContactForUpstream(msg, viaConfig)
			p.rewriteDomainForUpstream(msg, viaConfig)
			p.sendToBackend(protocol, msg, backend, viaConfig)
		} else {
			zap.L().Error("Not my message, fail to route the message")
		}
	} else {
		// Only pop the top Via if it belongs to this proxy.
		// When sendRequest uses ReceivedFrom.Send(), PBX strips the
		// proxy Via before returning the response, so the top Via is already
		// the phone's and must not be removed.
		via, viaErr := msg.GetVia()
		if viaErr == nil {
			topVia, paramErr := via.GetParam(0)
			if paramErr == nil && p.isMyVia(topVia) {
				msg.PopVia()
			}
		}
		host, port, transport, err := p.getNextReponseHop(msg)
		if err != nil {
			zap.L().Error("Fail to find the next hop for response", zap.String("message", msg.String()))
		} else {
			p.sendResponse(host, port, transport, msg)
		}
	}
}

// isMyVia returns true if the ViaParam matches any transport or viaConfig of this proxy.
func (p *Proxy) isMyVia(vp *ViaParam) bool {
	for _, item := range p.items {
		for _, t := range item.transports {
			if vp.Host == t.GetAddress() && vp.GetPort() == t.GetPort() {
				return true
			}
		}
		if item.viaConfig != nil {
			if vp.Host == item.viaConfig.Address && vp.GetPort() == item.viaConfig.Port {
				return true
			}
		}
	}
	return false
}

// learnRegistration stores user->LAN-phone-addr from a REGISTER Contact.
func (p *Proxy) learnRegistration(msg *Message) {
	method, err := msg.GetMethod()
	if err != nil || method != "REGISTER" {
		return
	}
	contactHdr, err := msg.GetHeader("Contact")
	if err != nil {
		return
	}
	contactStr, ok := contactHdr.value.(string)
	if !ok {
		return
	}
	expires := msg.GetExpires(300)
	start := strings.Index(contactStr, "<")
	// Find the FIRST ">" after start -- this closes the SIP URI angle bracket.
	// We must NOT use strings.LastIndex here because "Client Win" and similar
	// clients append a +sip.instance parameter containing another URI in angle
	// brackets, e.g.: <sip:user@host:port>;+sip.instance="<urn:uuid:...>"
	// strings.LastIndex would find the ">" that closes the UUID, producing an
	// address with a trailing ">" (e.g. "<phone-ip>:7327>") that is invalid
	// for net.SplitHostPort and breaks inbound call routing to that phone.
	endOffset := strings.Index(contactStr[start:], ">")
	if start == -1 || endOffset == -1 {
		return
	}
	end := start + endOffset
	uri := contactStr[start+1 : end]
	var body string
	if strings.HasPrefix(uri, "sip:") {
		body = uri[4:]
	} else if strings.HasPrefix(uri, "sips:") {
		body = uri[5:]
	} else {
		return
	}
	if semi := strings.Index(body, ";"); semi != -1 {
		body = body[:semi]
	}
	at := strings.Index(body, "@")
	if at == -1 {
		return
	}
	user := body[:at]
	addr := body[at+1:]
	if user == "" || !strings.Contains(addr, ":") {
		return
	}
	if expires == 0 {
		p.userRegistry.Delete(user)
		zap.L().Info("User registry: unregistered", zap.String("user", user))
	} else {
		p.userRegistry.Set(user, addr)
		zap.L().Info("User registry: learned", zap.String("user", user), zap.String("addr", addr))
	}
}

// routeToRegisteredPhone routes inbound INVITE/OPTIONS/etc. from PBX
// to the correct LAN phone using the user registry.
// Returns true if the message was handled.
// KEY: adds the proxy's own Via so the phone's response comes BACK through
// the proxy and is correctly forwarded to PBX - keeping pings alive.
func (p *Proxy) routeToRegisteredPhone(msg *Message, protocol string) bool {
	method, err := msg.GetMethod()
	if err != nil {
		return false
	}
	// REGISTER always goes upstream to PBX.
	if method == "REGISTER" {
		return false
	}
	to, err := msg.GetTo()
	if err != nil {
		return false
	}
	addrSpec, err := to.GetAddrSpec()
	if err != nil {
		return false
	}
	sipURI, err := addrSpec.GetSIPURI()
	if err != nil {
		return false
	}
	user := sipURI.User
	if user == "" {
		return false
	}

	// OPTIONS: ALWAYS respond 200 OK from the proxy, BEFORE checking userRegistry.
	//
	// Root cause of registration instability: learnRegistration() is called on the
	// phone's outbound REGISTER request. When a phone sends Expires:0 (deregister)
	// before re-registering -- which MicroSIP (Expires:300) and Client Win do every
	// 5 minutes -- the proxy immediately removes the user from userRegistry.
	//
	// If the old code's registry check ran first:
	//   userRegistry.Get(user) == false  -> return false  -> FS gets no 200 OK
	//   -> Ping-Status: Unreachable (32001ms timeout) -> registration expired.
	//
	// The proxy IS the SBC responsible for this user. It must always answer FS's
	// OPTIONS keepalive pings regardless of the phone's momentary registration
	// state. Even if the phone is mid-re-registration, the proxy is reachable.
	if method == "OPTIONS" {
		// When the tunnel is NOT authenticated (wrong or revoked auth-key):
		//   - Silently drop the OPTIONS ping instead of answering it.
		//   - FreeSWITCH waits ~32 s for a response, then marks the
		//     registration Unreachable and expires it.
		//   - This is the ONLY reliable mechanism to invalidate PBX-side
		//     registrations without needing to send a REGISTER Expires:0
		//     (which would require per-user auth credentials the proxy
		//     does not store).
		// When the tunnel IS authenticated: answer normally (keepalive OK).
		if atomic.LoadInt32(&p.tunnelBound) == 0 {
			zap.L().Warn("Tunnel not bound: dropping OPTIONS from PBX "+
				"(FS will mark Unreachable + expire registration in ~32s)",
				zap.String("user", user))
			return true // claimed as handled; no response sent intentionally
		}
		zap.L().Info("Proxy responding 200 OK to OPTIONS (SBC keepalive)",
			zap.String("user", user))
		p.respondOKToOptions(msg)
		return true
	}

	// For inbound INVITE/NOTIFY/BYE from PBX to a LAN phone:
	// if the tunnel is not authenticated, reject immediately with 480.
	// Without this check the call would still reach the phone because
	// routeToRegisteredPhone runs at step 2 BEFORE the gate at step 3.
	if atomic.LoadInt32(&p.tunnelBound) == 0 {
		zap.L().Warn("Tunnel not bound: rejecting inbound request from PBX with 480",
			zap.String("method", method), zap.String("user", user))
		p.rejectWithTemporarilyUnavailable(msg)
		return true
	}

	// For INVITE/NOTIFY/etc. the phone must be actively registered to route.
	if _, ok := p.userRegistry.Get(user); !ok {
		zap.L().Warn("routeToRegisteredPhone: no registry entry for user (phone not registered)",
			zap.String("method", method), zap.String("user", user))
		return false
	}

	// INVITE, NOTIFY, etc. forward to the LAN phone.
	phoneAddr, ok := p.userRegistry.Get(user)
	if !ok {
		return false
	}
	host, portStr, err := net.SplitHostPort(phoneAddr)
	if err != nil {
		return false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return false
	}
	// Bug fix: LAN phones register via UDP (or occasionally the proxy's TCP
	// server port). The `protocol` variable here is the protocol of the
	// INCOMING message (e.g. "tcp" when FS sends an INVITE on the FS->proxy
	// TCP connection). That is the INBOUND path from PBX, not the path TO
	// the phone. Using `protocol` directly caused:
	//
	//   selfLearnRoute.GetRoute("192.168.10.112", "tcp") -> not found
	//   -> return false
	//   -> B-leg INVITE falls through to outbound router -> bounced back to PBX
	//   -> PBX never hears from the phone -> call times out for the caller
	//
	// Fix: always probe for the phone's actual transport (UDP first, then TCP).
	serverTrans, ok := p.selfLearnRoute.GetRoute(host, "udp")
	if !ok {
		serverTrans, ok = p.selfLearnRoute.GetRoute(host, "tcp")
	}
	if !ok {
		zap.L().Warn("routeToRegisteredPhone: no selflearn route to phone (try both udp/tcp)",
			zap.String("user", user), zap.String("host", host))
		return false
	}
	zap.L().Info("Routing inbound request to LAN phone",
		zap.String("method", method), zap.String("user", user), zap.String("addr", phoneAddr))
	// Strip proxy-internal headers before delivering to phones.
	msg.RemoveHeader("X-Device-ID")
	// Add proxy Via so the phone's response (180/200 for INVITE, etc.) returns
	// through this proxy rather than going directly back to PBX.
	p.addVia(msg, serverTrans)
	// Add Record-Route so PBX keeps ALL subsequent in-dialog requests
	// (CANCEL before answer, BYE after answer, re-INVITEs for hold, etc.)
	// flowing through this proxy rather than going directly to the phone.
	//
	// Without Record-Route in the B-leg INVITE (PBX->phone direction):
	//   - PBX has no Route set for the established dialog
	//   - PBX may send CANCEL (for "caller hangs up before answer") directly
	//     to the phone's Contact URI, bypassing the proxy
	//   - The phone sees the CANCEL with PBX's Via branch (not the proxy's),
	//     but the pending INVITE had the PROXY's Via as the topmost entry
	//   - Branch mismatch -> phone ignores CANCEL -> phone keeps ringing forever
	//     even after the caller has hung up
	p.addRecordRoute(msg, serverTrans)
	if err := serverTrans.Send(host, port, msg); err != nil {
		zap.L().Error("Failed to send inbound request to phone",
			zap.String("user", user), zap.String("addr", phoneAddr), zap.Error(err))
	}
	return true
}

// rejectWithServiceUnavailable sends a 503 Service Unavailable response back
// to a LAN phone when the tunnel is not authenticated.  This happens when:
//   * The NX Device has a wrong or missing auth-key in sip-proxy.yaml
//   * The RingQ portal revoked the tunnel key after startup
//
// The phone receives a clean 503 immediately instead of spinning until
// its own INVITE/REGISTER timeout (typically 30-60 seconds).
// Log is at WARN level -- happens on every attempt until fixed.
func (p *Proxy) rejectWithServiceUnavailable(req *Message) {
	method, _ := req.GetMethod()
	zap.L().Warn("Tunnel not authenticated -- rejecting phone request with 503",
		zap.String("method", method),
		zap.String("hint", "set correct auth-key in sip-proxy.yaml and restart"))

	resp := NewResponseOf(req, 503, "Service Unavailable")
	
	resp.AddHeader("Retry-After", "60")

	// Copy mandatory response headers from request.
	for _, hdr := range []string{"Via", "From", "Call-ID", "CSeq", "To"} {
		v, err := req.GetHeaderValue(hdr)
		if err != nil {
			continue
		}
		switch val := v.(type) {
		case string:
			resp.AddHeader(hdr, val)
		case fmt.Stringer:
			resp.AddHeader(hdr, val.String())
		}
	}

	host, port, _, err := p.getNextReponseHop(resp)
	if err != nil {
		zap.L().Error("rejectWithServiceUnavailable: cannot determine response hop",
			zap.Error(err))
		return
	}
	if err := req.ReceivedFrom.Send(host, port, resp); err != nil {
		zap.L().Error("rejectWithServiceUnavailable: send failed", zap.Error(err))
	}
}

// respondOKToLocalDeregister sends a local 200 OK for a REGISTER Expires:0
// without forwarding the deregistration to the PBX.
//
// Why: When a phone (e.g. MicroSIP) sends Expires:0 before re-registering,
// the proxy intercepts it and answers locally. The PBX registration remains
// alive throughout, so:
//   - FS's keepalive OPTIONS ping keeps succeeding (TCP flow intact)
//   - No 32-second ping timeout -> no Unreachable -> no registration drop
//   - When the phone re-registers (Expires:N), the proxy forwards normally
//
// The phone's view: it successfully deregistered and re-registered.
// The PBX's view: the registration is simply refreshed with the new REGISTER.
func (p *Proxy) respondOKToLocalDeregister(req *Message) {
	resp := NewResponseOf(req, 200, "OK")

	if via, err := req.GetVia(); err == nil {
		resp.AddHeader("Via", via.String())
	} else {
		zap.L().Error("respondOKToLocalDeregister: cannot get Via", zap.Error(err))
		return
	}

	for _, hdr := range []string{"From", "Call-ID", "CSeq"} {
		if v, err := req.GetHeaderValue(hdr); err == nil {
			switch val := v.(type) {
			case string:
				resp.AddHeader(hdr, val)
			case fmt.Stringer:
				resp.AddHeader(hdr, val.String())
			}
		}
	}

	if to, err := req.GetTo(); err == nil {
		resp.AddHeader("To", to.String())
	} else {
		zap.L().Error("respondOKToLocalDeregister: cannot get To", zap.Error(err))
		return
	}

	resp.AddHeader("Content-Length", "0")

	host, port, transport, err := p.getNextReponseHop(resp)
	if err != nil {
		zap.L().Error("respondOKToLocalDeregister: cannot determine response hop", zap.Error(err))
		return
	}
	zap.L().Info("Responding 200 OK locally to REGISTER Expires:0 (PBX registration preserved)",
		zap.String("host", host), zap.Int("port", port))
	// Route via the correct send path. For phones (UDP), this resolves via
	// selfLearnRoute -> UDPClientTransport. Never uses TCPServerTransport.Send().
	p.sendResponse(host, port, transport, resp)
}

// respondOKToOptions builds and sends a 200 OK response directly to PBX
// for an OPTIONS request, without forwarding to the LAN phone.
//
// IMPORTANT -- type-safe header copying:
// Message.GetVia() and Message.GetTo() lazily parse their headers and replace
// header.value with a typed object (*Via, *To). Plain GetHeaderValue().(string)
// then silently fails. We must use the typed accessors and call .String() on
// the result. Specifically:
//   "Via"  -- SetReceived already called GetVia() -> header.value is *Via
//   "To"   -- routeToRegisteredPhone already called GetTo() -> header.value is *To
//   "From", "Call-ID", "CSeq" -- not yet parsed at this point -> still strings
//
// Sending via ReceivedFrom (the proxy's port-5060 server socket) lets the
// NAT gateway reuse the existing proxy->PBX NAT session for the outbound 200 OK.
func (p *Proxy) respondOKToOptions(req *Message) {
	resp := NewResponseOf(req, 200, "OK")

	// Via: header.value is already *Via (parsed by SetReceived). Use String().
	if via, err := req.GetVia(); err == nil {
		resp.AddHeader("Via", via.String())
	} else {
		zap.L().Error("respondOKToOptions: cannot get Via from OPTIONS", zap.Error(err))
		return
	}

	// From, Call-ID, CSeq: copy value regardless of whether it has been
	// lazily parsed into a typed object by earlier pipeline steps.
	// In particular, handleRawMessage calls msg.GetClientTransaction() which
	// parses the CSeq header (to extract the SIP method for the transaction
	// key) and caches it as a *CSeq object. A plain string assertion then
	// silently fails, leaving CSeq out of the response. CSeq is mandatory
	// in all SIP responses (RFC 3261 S8.1.1.6); without it FreeSWITCH
	// rejects the 200 OK as malformed, the Options ping times out after
	// 32 s, and the registration is marked Unreachable.
	for _, hdr := range []string{"From", "Call-ID", "CSeq"} {
		if v, err := req.GetHeaderValue(hdr); err == nil {
			switch val := v.(type) {
			case string:
				resp.AddHeader(hdr, val)
			case fmt.Stringer:
				resp.AddHeader(hdr, val.String())
			default:
				zap.L().Warn("respondOKToOptions: unhandled header type (skipped)",
					zap.String("header", hdr))
			}
		}
	}

	// To: header.value is *To (parsed by routeToRegisteredPhone->GetTo()). Use String().
	if to, err := req.GetTo(); err == nil {
		resp.AddHeader("To", to.String())
	} else {
		zap.L().Error("respondOKToOptions: cannot get To from OPTIONS", zap.Error(err))
		return
	}

	resp.AddHeader("Content-Length", "0")

	// Send via req.ReceivedFrom.Send().  TCPServerTransport.Send() now
	// writes directly to t.conn -- the exact TCP socket that received this
	// OPTIONS request -- with no clientTransMgr lookup.  This is simpler
	// and immune to the race where cleanExpiredTransport() removes the
	// transport entry during a concurrent re-registration burst, which
	// caused p.sendResponse() to silently drop the 200 OK.
	if req.ReceivedFrom == nil {
		zap.L().Error("respondOKToOptions: ReceivedFrom is nil")
		return
	}
	host, port, _, err := p.getNextReponseHop(resp)
	if err != nil {
		zap.L().Error("respondOKToOptions: cannot determine response hop", zap.Error(err))
		return
	}
	if err := req.ReceivedFrom.Send(host, port, resp); err != nil {
		zap.L().Error("respondOKToOptions: send failed", zap.Error(err))
	}
}

// rewriteContactForUpstream rewrites the REGISTER Contact to the proxy's
// PUBLIC (WAN) address so that PBX can reach the proxy for:
//   (a) OPTIONS keepalive pings -- PBX sends OPTIONS to the Contact to
//       verify the phone is still reachable; if the Contact is the proxy's
//       private LAN address (192.168.10.x) the cloud PBX can't route to it
//       and expires the registration with "options failure" after ~30-60 s.
//   (b) Inbound INVITEs -- when a call comes in, PBX sends the INVITE to
//       the registered Contact; again requires a routable address.
//
// The public address comes from the configured Via (e.g. 43.225.164.198:5060).
// PBX sends UDP to that address; the Fortigate VIP/DNAT forwards it to the
// proxy's LAN UDP listener (192.168.10.130:5060) where:
//   - OPTIONS are answered locally by respondOKToOptions (keepalive OK)
//   - INVITEs are routed to the LAN phone via routeToRegisteredPhone
//
// REQUIRED Fortigate configuration:
//   VIP: external 43.225.164.198 UDP 5060 -> internal 192.168.10.130:5060
//   Policy: allow inbound UDP 5060 from any to the VIP
func (p *Proxy) rewriteContactForUpstream(msg *Message, viaConfig *ViaConfig) {
	if viaConfig == nil {
		return
	}
	method, err := msg.GetMethod()
	if err != nil || method != "REGISTER" {
		return
	}
	contactHdr, err := msg.GetHeader("Contact")
	if err != nil {
		return
	}
	contactStr, ok := contactHdr.value.(string)
	if !ok {
		return
	}

	// Use the proxy's public address from the Via config so PBX can reach it.
	contactAddr := viaConfig.Address
	contactPort := viaConfig.Port
	if contactAddr == "" {
		// Fallback: use LAN listener address
		if len(p.items) == 0 || len(p.items[0].transports) == 0 {
			return
		}
		contactAddr = p.items[0].transports[0].GetAddress()
		contactPort = p.items[0].transports[0].GetPort()
	}

	newContact := rewriteContactURI(contactStr, contactAddr, contactPort)
	if newContact != contactStr {
		contactHdr.value = newContact
		zap.L().Info("Rewrote Contact for upstream (public IP so PBX can reach proxy for OPTIONS/INVITE)",
			zap.String("original", contactStr),
			zap.String("rewritten", newContact),
			zap.String("contact-addr", contactAddr),
			zap.Int("contact-port", contactPort))
	}
}

// rewriteDomainForUpstream rewrites the host (only) of the To and From
// headers in an outbound REGISTER to the RingQ PBX domain
// pbxDomain, regardless of what host the phone put there
// (typically the phone-configured LAN address, e.g. phonesDomain).
//
// See the pbxDomain field for the full rationale. In short:
// PBX resolves Auth-Realm and the dialplan "domain" from To/From host, not
// rewriteDomainForUpstream rewrites the host (only) of the To and From
// headers - and, for INVITE, also the Request-URI - from
// phonesDomain to pbxDomain
// before forwarding to the PBX.
//
// See the pbxDomain field for the full rationale. In short:
// PBX resolves Auth-Realm and the dialplan "domain"/context from the
// To/From/Request-URI host of REGISTER and INVITE, not from
// v_extensions.user_context. Without this rewrite PBX can't find a
// matching row in v_domains for phonesDomain and routes calls through
// the "public" (inbound-DID) dialplan context instead of the extension's
// own domain context, even when registration itself succeeds.
//
// For REGISTER, the Authorization "uri" param is left untouched - it still
// refers to the phonesDomain value, exactly what the phone signed in its
// digest response - so this does not affect auth validation.
//
// For INVITE, PBX does not challenge requests from an already-registered
// source (the proxy's rewritten Contact, 43.225.164.198:65476, matches the
// registration), so there is no digest signature over the Request-URI to
// preserve - rewriting it is safe.
//
// Only headers/Request-URI whose host is exactly phonesDomain are
// rewritten; anything else (e.g. PBX-originated addresses seen in in-dialog
// requests routed via Record-Route) is left alone.
func (p *Proxy) rewriteDomainForUpstream(msg *Message, viaConfig *ViaConfig) {
	if viaConfig == nil {
		return
	}
	// Skip when pbx-domain or phones-domain are not configured: rewriting
	// with an empty target would produce invalid SIP URIs ("sip:user@")
	// and cause the PBX to reject every REGISTER/INVITE.
	if p.pbxDomain == "" || p.phonesDomain == "" {
		return
	}
	method, err := msg.GetMethod()
	if err != nil {
		return
	}
	switch method {
	case "REGISTER", "INVITE":
	default:
		return
	}

	for _, headerName := range []string{"To", "From"} {
		hdr, err := msg.GetHeader(headerName)
		if err != nil {
			continue
		}
		// header.value may already be a typed *To/*FromSpec object if
		// GetTo()/GetFrom() was called earlier in the pipeline (e.g.
		// getNextRequestHopByConfig calls GetTo() for every message,
		// which lazily parses and replaces header.value with *To).
		// Accept either a plain string or anything with a String()
		// method (fmt.Stringer - *To and *FromSpec both implement it).
		var hdrStr string
		switch v := hdr.value.(type) {
		case string:
			hdrStr = v
		case fmt.Stringer:
			hdrStr = v.String()
		default:
			continue
		}
		newHdr := rewriteHostInAddrHeader(hdrStr, p.phonesDomain, p.pbxDomain)
		if newHdr != hdrStr {
			// Store back as a plain string. GetTo()/GetFrom() re-parse
			// string values into *To/*FromSpec on next access, so this
			// is safe for any later code that calls them again.
			hdr.value = newHdr
			zap.L().Info("Rewrote header host for upstream domain resolution",
				zap.String("method", method),
				zap.String("header", headerName),
				zap.String("original", hdrStr),
				zap.String("rewritten", newHdr))
		}
	}

	if method == "INVITE" || method == "REGISTER" {
		// REGISTER: phones send "REGISTER sip:192.168.10.130" (the proxy's LAN IP).
		// FS silently drops any REGISTER whose Request-URI domain it doesn't
		// recognise -- it never challenges, never logs, just discards.
		// Rewriting the Request-URI to the PBX domain makes FS accept it.
		p.rewriteRequestURIForUpstream(msg)
	}
}

// rewriteRequestURIForUpstream rewrites the host of the request's
// Request-URI from phonesDomain to pbxDomain, if it
// matches. See rewriteDomainForUpstream for the rationale.
func (p *Proxy) rewriteRequestURIForUpstream(msg *Message) {
	if msg.request == nil {
		return
	}
	uriStr := fmt.Sprintf("%v", msg.request.requestURI)
	newURIStr := rewriteHostInAddrHeader(uriStr, p.phonesDomain, p.pbxDomain)
	if newURIStr == uriStr {
		return
	}
	newAddrSpec, err := ParseAddrSpec(newURIStr)
	if err != nil {
		zap.L().Error("Failed to parse rewritten Request-URI",
			zap.String("original", uriStr),
			zap.String("rewritten", newURIStr),
			zap.Error(err))
		return
	}
	msg.request.requestURI = newAddrSpec
	zap.L().Info("Rewrote Request-URI host for upstream domain resolution",
		zap.String("original", uriStr),
		zap.String("rewritten", newURIStr))
}

// rewriteHostInAddrHeader replaces the host (and drops any explicit port)
// of the SIP URI inside a To/From-style header value (or a bare
// Request-URI) with newHost, but only if its current host is exactly
// oldHost. Handles both forms:
//
//	"Display" <sip:user@<phones-domain>:5060>;tag=...  (name-addr)
//	sip:user@<phones-domain>;tag=...                   (addr-spec / Request-URI)
//
// Display name, user part, tags and other parameters are preserved.
// If the current host is not oldHost, returns the header unchanged.
func rewriteHostInAddrHeader(header string, oldHost string, newHost string) string {
	start := strings.Index(header, "<")
	end := strings.Index(header, ">")
	var uriStart, uriEnd int
	if start != -1 && end != -1 && end > start {
		uriStart, uriEnd = start+1, end
	} else {
		// addr-spec form: sip:... up to the first ';' (params) or end of string
		uriStart = 0
		if !strings.HasPrefix(header, "sip:") && !strings.HasPrefix(header, "sips:") {
			return header
		}
		if semi := strings.IndexByte(header, ';'); semi != -1 {
			uriEnd = semi
		} else {
			uriEnd = len(header)
		}
	}
	uri := header[uriStart:uriEnd]
	sipURI, err := ParseSipURI(uri)
	if err != nil || sipURI.Host != oldHost {
		return header
	}
	sipURI.Host = newHost
	sipURI.port = 0
	newURI := sipURI.String()
	return header[:uriStart] + newURI + header[uriEnd:]
}

func (p *Proxy) addVia(msg *Message, transport ServerTransport) (*Via, error) {
	// Derive our own branch deterministically from the incoming top Via branch
	// (and Call-ID), instead of always generating a fresh random one.
	//
	// Without this, every forwarded message (including retransmissions of the
	// same request and the CANCEL for a pending INVITE) would get a brand new
	// random branch on this leg, which breaks transaction matching on the
	// upstream side:
	//   - Retransmissions of the same INVITE would look like "merged requests"
	//     (different branch, same Call-ID/From-tag/To/CSeq) and get a 482
	//     instead of a retransmitted provisional/final response.
	//   - A CANCEL for an INVITE must carry the SAME top Via branch as that
	//     INVITE (RFC 3261 9.1); if our added branch differs between the two,
	//     the upstream can't correlate the CANCEL to the pending INVITE
	//     transaction and the callee keeps ringing.
	//
	// UAs are required to keep the same branch across retransmissions and on
	// the CANCEL for an INVITE, so hashing that incoming branch (plus Call-ID)
	// reproduces the same proxy-branch in those cases, while still producing a
	// different branch for genuinely different transactions (e.g. ACK to 2xx).
	//
	// Via address: use the transport's CONFIGURED PUBLIC VIA address when
	// available (e.g. "43.225.164.198:5060" from the yaml "via" field),
	// not the raw bind address (e.g. "192.168.10.130:5060"). The raw bind
	// address is a private LAN IP that FreeSWITCH (running in the cloud)
	// cannot route responses back to. Without this, FS receives the REGISTER
	// over TCP from 43.225.164.198 but the Via header says 192.168.10.130;
	// FS silently drops the message due to IP mismatch, so no 401 challenge
	// is ever sent and registration never completes.
	viaAddr := transport.GetAddress()
	viaPort := transport.GetPort()
	viaProto := transport.GetProtocol()
	if udpTrans, ok := transport.(*UDPServerTransport); ok && udpTrans.via != nil {
		// UDPServerTransport has a configured public via (from yaml "via:" field).
		// Prefer it over the local bind address for the Via header.
		viaAddr = udpTrans.via.Address
		viaPort = udpTrans.via.Port
		viaProto = udpTrans.via.Protocol
		zap.L().Debug("addVia: using configured public via address",
			zap.String("viaAddr", viaAddr),
			zap.Int("viaPort", viaPort),
			zap.String("viaProto", viaProto))
	}
	var via *Via
	var err error
	if incomingBranch, branchErr := msg.GetTopViaBranch(); branchErr == nil && incomingBranch != "" {
		seed := incomingBranch
		if callId, idErr := msg.GetCallID(); idErr == nil && callId != "" {
			seed = callId + ":" + incomingBranch
		}
		var derivedBranch string
		derivedBranch, err = CreateBranchFromSeed(seed)
		if err == nil {
			via, err = CreateViaWithBranch(viaProto, viaAddr, viaPort, derivedBranch)
		}
	} else {
		via, err = CreateVia(viaProto, viaAddr, viaPort)
	}
	if err == nil {
		msg.AddVia(via)
	}
	return via, nil
}

func (p *Proxy) addRecordRoute(msg *Message, transport ServerTransport) {
	// if no Record-Route header is found and the mustRecordRoute is false, no need to add Record-Route header
	if _, err := msg.GetHeader("Record-Route"); err != nil && !p.mustRecordRoute {
		return
	}

	msg.AddRecordRoute(CreateRecordRoute(transport.GetAddress(), transport.GetPort()))
}

func (p *Proxy) sendToBackend(protocol string, msg *Message, preferBackend Backend, viaConfig *ViaConfig) {

	backendItem := p.findBackendProxyItem(protocol)
	if backendItem == nil && preferBackend == nil {
		zap.L().Error("Fail to find the backend for my message", zap.String("message", msg.String()))
	} else {
		sessionId, _ := msg.GetSessionId()
		backend, transport, err := p.findBackendBySessionId(protocol, sessionId)

		if err != nil && viaConfig != nil {
			transport, _ = p.findTransportByViaConfig(viaConfig)
		}

		if backend == nil && preferBackend != nil {
			backend = preferBackend
		}

		if transport == nil && backend != nil {
			backendAddrs := getAllBackendAddresses(backend)
			for _, addr := range backendAddrs {
				transport, err = p.findTransportByBackendAddr(addr, protocol)
				if err == nil {
					break
				}
			}
		}
		if backend == nil && backendItem != nil {
			backend = backendItem.backend
			transport = backendItem.transports[0]
		}
		if transport == nil && backendItem != nil {
			transport, _ = backendItem.FindTransport(func(t ServerTransport) bool {
				return t.GetProtocol() == protocol
			})
			if transport == nil {
				transport = backendItem.transports[0]
			}
		}
		if transport != nil {
			p.addVia(msg, transport)
			p.addRecordRoute(msg, transport)
		}
		if backend == nil {
			zap.L().Error("Fail to find backend for my message", zap.String("message", msg.String()))
			return
		}
		usedBackend, err := backend.Send(msg)
		if err == nil {
			zap.L().Debug("succeed to send the message to the backend", zap.String("backend", usedBackend.GetAddress()), zap.String("message", msg.String()))
			if len(sessionId) > 0 {
				// bind the backend with the transaction
				zap.L().Info("bind session with backend", zap.String("sessionId", sessionId), zap.String("backend", usedBackend.GetAddress()))
				p.sessionBackends.AddBackend(sessionId, usedBackend, msg.GetExpires(0))
			}
		} else {
			zap.L().Error("Fail to send the message to the backend", zap.String("backend", backend.GetAddress()), zap.String("message", msg.String()))
		}
	}
}

func (p *Proxy) findBackendBySessionId(protocol string, sessionId string) (Backend, ServerTransport, error) {
	// find the backend by session id
	backend, err := p.sessionBackends.GetBackend(sessionId)
	if err != nil {
		return nil, nil, fmt.Errorf("fail to find backend by session id %s", sessionId)
	}
	zap.L().Info("succeed to find backend by session id", zap.String("backendAddr", backend.GetAddress()), zap.String("sessionId", sessionId))
	transport, _ := p.findTransportByBackendAddr(backend.GetAddress(), protocol)
	return backend, transport, nil
}

func (p *Proxy) findTransportByViaConfig(viaConfig *ViaConfig) (ServerTransport, error) {
	if viaConfig == nil {
		return nil, fmt.Errorf("no via config")
	}
	for _, item := range p.items {
		transport, err := item.FindTransport(func(transport ServerTransport) bool {
			return transport.GetProtocol() == viaConfig.Protocol && transport.GetAddress() == viaConfig.Address && transport.GetPort() == viaConfig.Port
		})
		if err == nil {
			zap.L().Info("succeed to find transport by via config", zap.String("viaConfig", viaConfig.String()))
			return transport, err
		}
	}
	return nil, fmt.Errorf("fail to find transport by via config")
}

func (p *Proxy) findTransportByBackendAddr(addr string, preferProtocol string) (ServerTransport, error) {
	for _, item := range p.items {
		transport, err := item.FindTransport(func(serverTransport ServerTransport) bool {
			return serverTransport.GetAddress() == addr
		})

		if err == nil {
			return transport, err
		}
	}

	for _, item := range p.items {
		transport, err := item.FindTransport(func(serverTransport ServerTransport) bool {
			return serverTransport.GetProtocol() == preferProtocol
		})
		if err == nil {
			return transport, err
		}
	}

	return nil, fmt.Errorf("fail to find backend by %s", addr)
}

func (p *Proxy) findBackendProxyItem(protocol string) *ProxyItem {
	for _, item := range p.items {
		if item.backend != nil && strings.HasPrefix(item.backend.GetAddress(), protocol) {
			return item
		}
	}
	return nil
}

func (p *Proxy) getNextRequestHop(msg *Message) (host string, port int, transport string, err error) {
	host, port, transport, err = p.getNextRequestHopByRoute(msg)
	if err == nil {
		return host, port, transport, err
	}
	return p.getNextRequestHopByConfig(msg)

}

func (p *Proxy) getNextRequestHopByConfig(msg *Message) (host string, port int, transport string, err error) {
	to, err := msg.GetTo()
	if err != nil {
		return "", 0, "", fmt.Errorf("no To header in message")
	}
	destHost, err := to.GetHost()
	if err != nil {
		return "", 0, "", fmt.Errorf("fail to find Host in To header of message")
	}
	transport, host, port, err = p.preConfigRoute.FindRoute(destHost)
	return
}

func (P *Proxy) getNextRequestHopByRoute(msg *Message) (host string, port int, transport string, err error) {

	route, err := msg.GetRoute()
	if err != nil {
		return
	}
	routeParam, err := route.GetRouteParam(0)
	if err != nil {
		return
	}
	if !P.keepNextHopRoute {
		msg.PopRoute()
	}
	addr := routeParam.GetAddress().GetAddress()
	if addr.IsSIPURI() {
		sipUri, _ := addr.GetSIPURI()
		transport = sipUri.GetTransport()
		host = sipUri.Host
		port = sipUri.GetPort()
	} else {
		err = fmt.Errorf("address %v is not a sip URI", addr)
	}
	return
}

func (p *Proxy) getNextReponseHop(msg *Message) (host string, port int, protocol string, err error) {
	via, err := msg.GetVia()
	if err != nil {
		return
	}
	viaParam, err := via.GetParam(0)
	if err != nil {
		return
	}
	protocol = viaParam.Transport
	host, err = viaParam.GetReceived()
	if err == nil {
		port, err = viaParam.GetRPort()
		if err != nil {
			port = viaParam.GetPort()
		}
		err = nil
	} else {
		host = viaParam.Host
		port = viaParam.GetPort()
		err = nil
	}
	return
}

func (p *Proxy) findClientTransport(host string, port int, protocol string, transId string) (ClientTransport, error) {
	if serverTrans, ok := p.selfLearnRoute.GetRoute(host, protocol); ok {
		udpServerTrans, ok := serverTrans.(*UDPServerTransport)
		if ok {
			// if the transport is UDP, create a new UDP client transport
			localAddr := ":0"
			if udpServerTrans.conn.LocalAddr() != nil {
				localAddr = udpServerTrans.conn.LocalAddr().String()
				localAddr, _, _ = net.SplitHostPort(localAddr)
				localAddr = net.JoinHostPort(localAddr, "0")
			}
			if localAddr == "" {
				localAddr = ":0"
			}
			return p.clientTransportFactory.CreateUDPClientTransport(host, port, localAddr)
		}
	}

	return p.clientTransMgr.GetTransport(protocol, host, port, transId)
}

func (p *Proxy) sendRequest(host string, port int, protocol string, msg *Message) {
	// For TCP destinations (e.g. PBX on port 6010) we must use the client
	// transport manager because ReceivedFrom is typically a UDP server socket
	// (the phone's inbound socket) and cannot send TCP.
	if strings.EqualFold(protocol, "tcp") {
		t, err := p.findClientTransport(host, port, protocol, "")
		if err == nil {
			if sendErr := t.Send(msg); sendErr != nil {
				callId, _ := msg.GetCallID()
				zap.L().Error("Fail to send request via TCP transport",
					zap.String("call-id", callId), zap.Error(sendErr))
			}
		} else {
			zap.L().Error("Fail to find TCP transport for request",
				zap.String("host", host), zap.Int("port", port))
		}
		return
	}
	// UDP: reuse the socket that received the original message when available.
	if msg.ReceivedFrom != nil {
		if err := msg.ReceivedFrom.Send(host, port, msg); err != nil {
			callId, _ := msg.GetCallID()
			zap.L().Error("Fail to send request via receiving transport", zap.String("call-id", callId), zap.Error(err))
		}
		return
	}
	t, err := p.findClientTransport(host, port, protocol, "")
	if err == nil {
		if t.Send(msg) != nil {
			callId, _ := msg.GetCallID()
			zap.L().Error("Fail to send message", zap.String("call-id", callId))
		}
	} else {
		zap.L().Error("Fail to find the transport to send request message", zap.String("host", host), zap.Int("port", port), zap.String("transport", protocol), zap.String("message", msg.String()))
	}
}

func (p *Proxy) sendResponse(host string, port int, protocol string, msg *Message) {
	transId, _ := msg.GetClientTransaction()
	t, err := p.findClientTransport(host, port, protocol, transId)
	if err == nil {
		if msg.IsFinalResponse() {
			// remove the transport from the client transaction manager
			p.clientTransMgr.RemoveTransport(protocol, host, port, transId)
		}
		t.Send(msg)
	} else {
		zap.L().Error("Fail to find the transport to send response", zap.String("host", host), zap.Int("port", port), zap.String("transport", protocol), zap.String("message", msg.String()))
	}
}

// NewProxyItem create a sip proxy
func NewProxyItem(listenConfig ListenConfig,
	receivedSupport bool,
	connAcceptedListener ConnectionAcceptedListener,
	selfLearnRoute *SelfLearnRoute,
	msgHandler MessageHandler) (*ProxyItem, error) {
	zap.L().Info("NewProxyItem", zap.Any("listenConfig", listenConfig), zap.Bool("receivedSupport", receivedSupport))

	proxyItem := &ProxyItem{transports: make([]ServerTransport, 0),
		viaConfig:  createViaConfig(listenConfig.Via),
		backend:    nil,
		msgHandler: msgHandler,
	}

	connectionEstablished := func(conn net.Conn) {
		zap.L().Info("tcp connection established", zap.String("remoteAddr", conn.RemoteAddr().String()), zap.String("localAddr", conn.LocalAddr().String()))
		proxyItem.connectionEstablished(conn, receivedSupport, selfLearnRoute)
	}

	proxyItem.backend, _ = CreateRoundRobinBackend(listenConfig.Backends, connectionEstablished)

	if listenConfig.UdpPort > 0 {
		udpServerTrans, err := NewUDPServerTransport(listenConfig.Address, listenConfig.UdpPort, receivedSupport, selfLearnRoute, proxyItem.viaConfig, proxyItem.backend)
		if err == nil {
			proxyItem.transports = append(proxyItem.transports, udpServerTrans)
		}
	}

	if listenConfig.TcpPort > 0 {
		proxyItem.transports = append(proxyItem.transports, NewTCPServerTransport(listenConfig.Address, listenConfig.TcpPort, receivedSupport, connAcceptedListener, selfLearnRoute, proxyItem.viaConfig, proxyItem.backend))
	}

	return proxyItem, nil
}

func (p *ProxyItem) FindTransport(cond func(serverTransport ServerTransport) bool) (ServerTransport, error) {
	for _, transport := range p.transports {
		if cond(transport) {
			return transport, nil
		}
	}
	return nil, fmt.Errorf("fail to find transport")

}

func (p *ProxyItem) findBackendByAddr(address string) (Backend, error) {
	if p.backend == nil {
		return nil, fmt.Errorf("no backend for proxy item")
	}

	return p.backend.GetBackend(address) // ensure the backend is initialized
}

func (p *ProxyItem) connectionEstablished(conn net.Conn, receivedSupport bool, selfLearnRoute *SelfLearnRoute) {
	p.Lock()
	defer p.Unlock()

	p.removeExitServerTransports()
	trans := NewTCPServerTransportWithConn(conn, receivedSupport, selfLearnRoute, p.backend)
	p.transports = append(p.transports, trans)
	trans.Start(p.msgHandler)

}

func (p *ProxyItem) removeExitServerTransports() {
	ok_transports := make([]ServerTransport, 0)

	for _, transport := range p.transports {
		if !transport.IsExit() {
			ok_transports = append(ok_transports, transport)
		}
	}

	if len(ok_transports) != len(p.transports) {
		p.transports = ok_transports
	}

}

func (p *ProxyItem) Start() error {
	for _, trans := range p.transports {
		err := trans.Start(p.msgHandler)
		if err != nil {
			return err
		}
	}
	return nil
}

// addTunnelAuthHeaders injects identifying headers into every SIP request
// forwarded from this proxy to the PBX. Authentication is handled by the
// REST API (bind + heartbeat) -- these headers are for PBX-side logging,
// tracing, and diagnostics only. No Lua per-message validation is required.
//
//   X-Device-ID  - NX Device unique ID (/etc/machine-id); lets the PBX log
//                  which physical device sent each SIP message
//
// Headers are injected on the outbound (proxy->PBX) path only and stripped
// before forwarding any message to the LAN phones.
// No-op when auth is not configured.
func (p *Proxy) addTunnelAuthHeaders(msg *Message) {
	if p.authKey == "" || p.deviceID == "" {
		return
	}
	msg.AddHeader("X-Device-ID", p.deviceID)
}


// TunnelStatusOffline and TunnelStatusOnline are the status codes sent to the
// PBX via POST /tunnel/status so the Tunnel Connections UI stays accurate.
const (
	TunnelStatusOffline = 0
	TunnelStatusOnline  = 1
)

// reportTunnelStatus POSTs the proxy's current online/offline state to the
// PBX portal.  The PBX stores the value in tunnel_config.status and surfaces
// it in the Tunnel Connections UI (ONLINE / OFFLINE badge).
//
// Call sites:
//   bindDevice() success     -> status=1  (ONLINE, gate just opened)
//   heartbeatLoop() 200 OK   -> status=1  (ONLINE, keeps last_seen fresh)
//   heartbeatLoop() 401/403  -> status=0  (OFFLINE, auth revoked)
//   graceful shutdown signal -> status=0  (OFFLINE, immediate notification)
//
// This is always best-effort: errors are logged but never block the caller.
// Timeout is 5 s so shutdown is not delayed on network issues.
//
// Request JSON: {"auth_key":..., "device_id":..., "domain":..., "status": 0|1}
// Expected response: HTTP 200  (body ignored)
func (p *Proxy) reportTunnelStatus(status int) {
	if p.apiBaseURL == "" || p.authKey == "" || p.deviceID == "" {
		// No auth configured -- open/dev mode, no status reporting.
		return
	}

	base := p.apiBaseURL
	if base == "" {
		base = fmt.Sprintf("https://%s", p.pbxDomain)
	}
	statusURL := base + "/tunnel/status"

	type statusRequest struct {
		AuthKey  string `json:"auth_key"`
		DeviceID string `json:"device_id"`
		Domain   string `json:"domain"`
		Status   int    `json:"status"` // 0=offline, 1=online
		LocalIP  string `json:"local_ip,omitempty"`
	}
	payload, err := json.Marshal(statusRequest{
		AuthKey:  p.authKey,
		DeviceID: p.deviceID,
		Domain:   p.pbxDomain,
		Status:   status,
		LocalIP:  p.phonesDomain, // LAN IP phones connect to
	})
	if err != nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		statusURL, bytes.NewBuffer(payload))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := tunnelHTTPClient.Do(req)
	if err != nil {
		// OFFLINE failures are logged at Warn (shutdown path, worth surfacing).
		// ONLINE failures are logged at Debug only -- heartbeatLoop retries
		// this every interval, so Warn-level here would spam the log, but
		// staying fully silent previously made a real, persistent failure
		// invisible. Run with --log-level Debug to see these.
		if status == TunnelStatusOffline {
			zap.L().Warn("reportTunnelStatus: could not send OFFLINE to PBX",
				zap.String("pbx-domain", p.pbxDomain),
				zap.Error(err))
		} else {
			zap.L().Debug("reportTunnelStatus: could not send ONLINE to PBX",
				zap.String("pbx-domain", p.pbxDomain),
				zap.Error(err))
		}
		return
	}
	defer resp.Body.Close()

	label := "OFFLINE"
	if status == TunnelStatusOnline {
		label = "ONLINE"
	}
	if resp.StatusCode == http.StatusOK {
		zap.L().Debug("Tunnel status reported to PBX",
			zap.String("status", label),
			zap.String("pbx-domain", p.pbxDomain))
	} else {
		zap.L().Warn("Tunnel status report not accepted by PBX",
			zap.Int("http-status", resp.StatusCode),
			zap.String("status", label),
			zap.String("pbx-domain", p.pbxDomain))
	}
}

// clearUserRegistry immediately removes all user->addr mappings.
// Called when tunnel auth is revoked so that:
//   - routeToRegisteredPhone() finds no entries -> inbound INVITE rejected
//   - Phones must re-register when the tunnel is restored
// Thread-safe.
func (p *Proxy) clearUserRegistry() {
	p.userRegistry.Lock()
	p.userRegistry.m = make(map[string]string)
	p.userRegistry.Unlock()
	zap.L().Info("User registry cleared (all LAN phone mappings removed)")
}

// rejectWithTemporarilyUnavailable sends 480 Temporarily Unavailable back
// to the PBX for an inbound INVITE/NOTIFY when the tunnel is not bound.
// 480 tells the PBX "callee temporarily unavailable" so it can play an
// appropriate announcement to the calling party, rather than the generic
// 503 Service Unavailable used for phone->PBX blocking.
func (p *Proxy) rejectWithTemporarilyUnavailable(req *Message) {
	method, _ := req.GetMethod()
	zap.L().Warn("Tunnel not bound: sending 480 Temporarily Unavailable to PBX",
		zap.String("method", method))

	resp := NewResponseOf(req, 480, "Temporarily Unavailable")
	resp.AddHeader("Retry-After", "30")

	for _, hdr := range []string{"Via", "From", "Call-ID", "CSeq", "To"} {
		v, err := req.GetHeaderValue(hdr)
		if err != nil {
			continue
		}
		switch val := v.(type) {
		case string:
			resp.AddHeader(hdr, val)
		case fmt.Stringer:
			resp.AddHeader(hdr, val.String())
		}
	}

	host, port, _, err := p.getNextReponseHop(resp)
	if err != nil {
		zap.L().Error("rejectWithTemporarilyUnavailable: cannot determine hop",
			zap.Error(err))
		return
	}
	if req.ReceivedFrom == nil {
		return
	}
	if err := req.ReceivedFrom.Send(host, port, resp); err != nil {
		zap.L().Error("rejectWithTemporarilyUnavailable: send failed", zap.Error(err))
	}
}

// bindDevice calls the PBX provisioning API to register this NX Device.
// It validates the domain+auth_key combination and binds this device_id to
// the tunnel record. The SIP service should not start until this succeeds.
// Retries indefinitely with exponential backoff (max 60s between attempts).
//
// PBX endpoint: POST https://<pbxDomain>/api/v1/tunnel/bind
//   Body:    { "domain": "...", "auth_key": "...", "device_id": "...", "public_ip": "..." }
//   Returns: 200 OK on success; 403 if domain/key/device mismatch
// bindDevice registers this NX Device with the RingQ Cloud PBX by POSTing
// to the tunnel bind API. The PBX looks up the auth_key in tunnel_config and:
//   - First call (device_id IS NULL):  binds device_id, records both IPs
//   - Later calls (device_id IS SET):  verifies device_id matches, updates IPs
//
// Maps to tunnel_config columns:
//   auth_key        -> lookup key (unique per tunnel in portal)
//   device_id       -> from /etc/machine-id  (bound on first call)
//   device_public_ip -> office NAT IP        (updated on every call)
//   device_local_ip  -> NX Device LAN IP     (updated on every call)
//   last_seen        -> set to NOW()         (updated on every call)
//   updated_at       -> set to NOW()         (updated on every call)
//
// No Lua validation is needed -- the API handles all authentication.
// Retries with exponential backoff (max 60s) until PBX confirms.
func (p *Proxy) bindDevice() {
	if p.authKey == "" || p.deviceID == "" {
		zap.L().Warn("Tunnel auth-key or device-id not configured -- skipping bind")
		return
	}

	base := p.apiBaseURL
	if base == "" {
		base = fmt.Sprintf("https://%s", p.pbxDomain)
	}
	bindURL := base + "/tunnel/bind"
	backoff := 5 * time.Second

	// device_local_ip = proxy LAN listen address (phones connect to this)
	deviceLocalIP := p.phonesDomain

	for attempt := 1; ; attempt++ {
		devicePublicIP := p.detectPublicIP()

		// JSON body maps directly to tunnel_config column names
		body := fmt.Sprintf(
			`{"auth_key":%q,"device_id":%q,"device_public_ip":%q,"device_local_ip":%q}`,
			p.authKey, p.deviceID, devicePublicIP, deviceLocalIP,
		)

		resp, err := tunnelHTTPClient.Post(bindURL, "application/json", bytes.NewBufferString(body))
		if err == nil {
			// Read the full response body so we can inspect it.
			// Some PBX implementations return HTTP 200 with
			// {"status": false, "message": "..."} for auth failures
			// instead of the more correct HTTP 403. We handle both.
			rawBody, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			switch resp.StatusCode {
			case http.StatusOK:
				// Double-check the JSON body -- PBX may return 200 with
				// status:false to signal auth failure.
				if isBindSuccess(rawBody) {
					atomic.StoreInt32(&p.tunnelBound, 1) // open the SIP gate
					go p.reportTunnelStatus(TunnelStatusOnline)  // tell portal: ONLINE
					zap.L().Info("NX Device bind successful",
						zap.String("pbx-domain", p.pbxDomain),
						zap.String("device-id", p.deviceID),
						zap.String("device-public-ip", devicePublicIP),
						zap.String("device-local-ip", deviceLocalIP))
					return
				}
				// HTTP 200 but body says failure -- treat as auth error.
				msg := extractMessage(rawBody)
				// tunnelBound stays false -- phones will see 503 Service Unavailable
				zap.L().Error("NX Device bind rejected by PBX (auth failed) -- "+
					"check auth-key in YAML. All SIP traffic is BLOCKED until fixed.",
					zap.String("pbx-response", msg),
					zap.String("pbx-domain", p.pbxDomain),
					zap.String("device-id", p.deviceID))
				return // wrong key -- no point retrying

			case http.StatusForbidden:
				// 403 = standard REST rejection (auth_key not found or
				// device_id already bound to a different machine).
				msg := extractMessage(rawBody)
				// tunnelBound stays false -- phones will see 503 Service Unavailable
				zap.L().Error("NX Device bind rejected by PBX (403) -- "+
					"check auth-key in YAML. All SIP traffic is BLOCKED until fixed.",
					zap.String("pbx-response", msg),
					zap.String("pbx-domain", p.pbxDomain),
					zap.String("device-id", p.deviceID))
				return // fatal -- no point retrying

			default:
				zap.L().Warn("Bind attempt failed -- unexpected HTTP status",
					zap.Int("http-status", resp.StatusCode),
					zap.String("pbx-body", string(rawBody)),
					zap.Int("attempt", attempt),
					zap.Duration("retry-in", backoff))
			}
		} else {
			zap.L().Warn("Bind attempt failed -- PBX unreachable",
				zap.Int("attempt", attempt),
				zap.Duration("retry-in", backoff),
				zap.Error(err))
		}

		time.Sleep(backoff)
		if backoff < 60*time.Second {
			backoff *= 2
		}
	}
}

// heartbeatLoop sends a periodic POST to the PBX so it can update the
// tunnel's Online/Offline status in the portal. Runs every heartbeatInterval
// after a successful bindDevice call.
//
// PBX endpoint: POST https://<pbxDomain>/api/v1/tunnel/heartbeat
//   Body: { "domain": "...", "auth_key": "...", "device_id": "..." }
// heartbeatLoop sends a POST to the PBX every 60 seconds so the portal
// can show this NX Device as Online/Offline.
//
// PBX API updates tunnel_config:
//   SET last_seen = NOW(), updated_at = NOW()
//   WHERE auth_key = ? AND device_id = ?
//
// The portal determines Online/Offline by checking whether
// last_seen is within the last 2 minutes (recommended threshold).
func (p *Proxy) heartbeatLoop() {
	const heartbeatInterval = 60 * time.Second

	if p.authKey == "" || p.deviceID == "" {
		return
	}

	base := p.apiBaseURL
	if base == "" {
		base = fmt.Sprintf("https://%s", p.pbxDomain)
	}
	hbURL := base + "/tunnel/heartbeat"
	// Minimal body -- PBX looks up by auth_key + device_id
	body := fmt.Sprintf(`{"auth_key":%q,"device_id":%q}`, p.authKey, p.deviceID)

	for {
		time.Sleep(heartbeatInterval)
		resp, err := tunnelHTTPClient.Post(hbURL, "application/json", bytes.NewBufferString(body))
		if err != nil {
			zap.L().Warn("Heartbeat: PBX unreachable",
				zap.String("pbx-domain", p.pbxDomain),
				zap.Error(err))
			continue
		}
		resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusOK:
			if atomic.LoadInt32(&p.tunnelBound) == 0 {
				atomic.StoreInt32(&p.tunnelBound, 1) // re-open the SIP gate
				zap.L().Info("Heartbeat: tunnel restored -- SIP gate re-opened",
					zap.String("pbx-domain", p.pbxDomain))
			} else {
				zap.L().Debug("Heartbeat OK", zap.String("pbx-domain", p.pbxDomain))
			}
			// Update portal status to ONLINE (also refreshes last_seen).
			go p.reportTunnelStatus(TunnelStatusOnline)
		case http.StatusUnauthorized, http.StatusForbidden:
			// Explicit revocation -- close the gate, clear the local registry,
			// and tell the portal immediately.
			//
			// Clearing the registry has two effects:
			//   1. routeToRegisteredPhone() no longer finds any user, so
			//      inbound INVITE from PBX falls through to the tunnel gate
			//      (step 3 in handleMessage) and is rejected with 503.
			//   2. The OPTIONS drop (above) causes FS to time out (~32 s) and
			//      expire the PBX-side registrations automatically.
			// Together these two mechanisms ensure that within ~32 seconds of
			// auth revocation: no inbound calls reach phones, no outbound
			// calls leave the LAN, and FS has no stale registrations.
			atomic.StoreInt32(&p.tunnelBound, 0)
			p.clearUserRegistry()
			go p.reportTunnelStatus(TunnelStatusOffline)
			zap.L().Error("Heartbeat: auth rejected -- SIP gate CLOSED, all registrations cleared",
				zap.Int("http-status", resp.StatusCode),
				zap.String("pbx-domain", p.pbxDomain))
		default:
			// Transient error -- do NOT close the gate (keep active calls alive).
			zap.L().Warn("Heartbeat: transient error (gate unchanged)",
				zap.Int("http-status", resp.StatusCode),
				zap.String("pbx-domain", p.pbxDomain))
		}
	}
}

// isBindSuccess inspects the JSON body returned by POST /tunnel/bind and
// returns true only when the PBX explicitly signals success.
//
// The PBX may return either:
//   HTTP 200 + { "status": true,  ... }  -> bound OK
//   HTTP 200 + { "status": false, ... }  -> auth failure (non-standard but seen in practice)
//   HTTP 200 + { "status": "bound", ... }-> bound OK (string variant)
//
// Anything other than a clear success signal is treated as failure.
func isBindSuccess(body []byte) bool {
	s := strings.TrimSpace(string(body))
	// Quick check: does the body contain an obvious success marker?
	// Handles: {"status":true}, {"status":"true"}, {"status":"bound"}, {"status":"ok"}
	if strings.Contains(s, `"status":true`) ||
		strings.Contains(s, `"status": true`) ||
		strings.Contains(s, `"status":"bound"`) ||
		strings.Contains(s, `"status": "bound"`) ||
		strings.Contains(s, `"status":"ok"`) ||
		strings.Contains(s, `"status": "ok"`) {
		return true
	}
	return false
}

// extractMessage pulls the "message" string from a JSON body for logging.
// Returns the raw body if parsing fails.
func extractMessage(body []byte) string {
	s := string(body)
	const key = `"message":`
	idx := strings.Index(s, key)
	if idx == -1 {
		return s
	}
	rest := strings.TrimSpace(s[idx+len(key):])
	if len(rest) == 0 {
		return s
	}
	if rest[0] == '"' {
		end := strings.Index(rest[1:], `"`)
		if end != -1 {
			return rest[1 : end+1]
		}
	}
	return rest
}

// detectPublicIP attempts to discover this device's public IP by querying
// a well-known external service. Used when reporting to the PBX bind API.
// Returns empty string on failure (PBX can learn the IP from the HTTP request).
func (p *Proxy) detectPublicIP() string {
	for _, url := range []string{
		"https://api.ipify.org",
		"https://ifconfig.me",
	} {
		resp, err := http.Get(url) //nolint:gosec
		if err != nil {
			continue
		}
		buf := make([]byte, 64)
		n, _ := resp.Body.Read(buf)
		resp.Body.Close()
		if n > 0 {
			return strings.TrimSpace(string(buf[:n]))
		}
	}
	return ""
}

// rewriteContactURI replaces the host:port in a Contact header value with
// newHost:newPort. It preserves the display name, URI parameters (especially
// ;ob for RFC 5626 outbound flow routing), and Contact header parameters.
// It strips only the 'transport' URI parameter (transport is controlled via
// the Via header, not the Contact URI).
//
// The ;ob parameter (RFC 5626) is ADDED if not already present. When ;ob is
// in the Contact, FreeSWITCH delivers inbound INVITEs and OPTIONS keepalive
// pings back on the SAME TCP connection that was used for REGISTER. This
// means the proxy does NOT need a Fortigate VIP for inbound traffic -- all
// PBX->proxy traffic travels on the persistent proxy->PBX TCP connection.
//
// Example: "Display" <sip:user@<phone-ip>:60984;ob>
//
//	-> "RT 1000" <sip:user@43.225.164.198:5060;ob>
func rewriteContactURI(contact string, newHost string, newPort int) string {
	start := strings.Index(contact, "<")
	end := strings.Index(contact, ">")
	if start == -1 || end == -1 || end <= start {
		return contact
	}
	uri := contact[start+1 : end]
	sipURI, err := ParseSipURI(uri)
	if err != nil {
		return contact
	}
	// Build URI parameters: override 'transport' to tcp, keep everything else
	// (especially ;ob for RFC 5626 outbound flow routing).
	//
	// WHY transport=tcp must be in the Contact (not just the Via):
	//   The Via transport tells FS how to send RESPONSES back to the proxy.
	//   The Contact transport tells FS how to classify and reach this endpoint.
	//
	//   Without transport=tcp: FS registers the phone as Registered(UDP-NAT)
	//   and periodically fires nat-options-ping via UDP to 43.225.164.198:5060.
	//   The Fortigate has no UDP/5060 VIP -> packet dropped -> 32 s timeout ->
	//   Ping-Status: Unreachable -> registration expires.
	//
	//   With transport=tcp: FS registers the phone as Registered(TCP-NAT) and
	//   uses the established TCP/6010 flow (identified by fs_path and ;ob) for
	//   both keepalive liveness checks and inbound call delivery.  The CRLF
	//   keepalive pings sent by the proxy every 30 s keep that flow alive, so
	//   FS marks the endpoint Reachable via Ping-Time: 0.00 indefinitely.
	//   No Fortigate VIP or FS nat-options-ping setting change required.
	var params []string
	hasOb := false
	for _, p := range sipURI.Parameters {
		if strings.EqualFold(p.Key, "transport") {
			continue // replaced by transport=tcp below
		}
		if strings.EqualFold(p.Key, "ob") {
			hasOb = true
		}
		if p.Value != "" {
			params = append(params, p.Key+"="+p.Value)
		} else {
			params = append(params, p.Key)
		}
	}
	// Force transport=tcp so FS classifies this as a TCP-NAT registration.
	params = append(params, "transport=tcp")
	// Always ensure ;ob is present (RFC 5626 outbound flow routing).
	// With ;ob + fs_path, FS delivers INVITEs via the TCP/6010 tunnel,
	// not to the Contact address directly.
	if !hasOb {
		params = append(params, "ob")
	}
	newURI := fmt.Sprintf("sip:%s@%s:%d", sipURI.User, newHost, newPort)
	if len(params) > 0 {
		newURI += ";" + strings.Join(params, ";")
	}
	return contact[:start+1] + newURI + contact[end:]
}

// sendSynthetic100Trying generates a 100 Trying and sends it directly to the
// INVITE caller immediately after the proxy has forwarded the INVITE upstream.
//
// WHY THIS IS NEEDED:
// PBX sends its own 100 Trying to the proxy with only the proxy's Via
// in the header (one Via total). When the proxy strips that Via, nothing
// remains -> ERROR, and the message is never forwarded to the original caller.
//
// PJSIP-based clients (MicroSIP, PortSIP) strictly follow RFC 3261 9.1:
// "A UAC SHOULD NOT send CANCEL if it has not received a provisional response."
// In practice PJSIP queues the CANCEL and waits for any 1xx before sending.
// Without receiving a 1xx, the user can hang up the call but the client
// never sends CANCEL -- the callee keeps ringing for the full 30-second PBX
// no-answer timeout (as seen empirically: PBX sends B-leg CANCEL at exactly
// T=30s with Reason: Q.850;cause=19;text="NO_ANSWER").
//
// Sending our own 100 Trying using the caller's original Via (captured before
// addVia prepended the proxy's Via) moves the caller into PROCEEDING state,
// after which PJSIP sends CANCEL immediately when the user hangs up.
// This fixes Scenarios 9 (MicroSIP->Yealink), 10 (MicroSIP->PortSIP), and
// 12 (PortSIP->Yealink) where "caller cancels before answer" was broken.
//
// callerViaStr: the caller's original Via parameter string captured before
// addVia was called. Empty string is a no-op (non-INVITE or Via capture failed).
func (p *Proxy) sendSynthetic100Trying(req *Message, callerViaStr string) {
	if callerViaStr == "" {
		return
	}
	method, err := req.GetMethod()
	if err != nil || method != "INVITE" {
		return
	}
	if req.ReceivedFrom == nil {
		return
	}

	// Build a minimal 100 Trying containing only the caller's original Via.
	resp := NewResponseOf(req, 100, "Trying")
	resp.AddHeader("Via", callerViaStr)

	// Echo From, To, Call-ID, CSeq back to the caller.
	// From/To may have been rewritten to pbxDomain by
	// rewriteDomainForUpstream, but PJSIP matches responses to transactions
	// by Via branch + From-tag + Call-ID -- not by To/From host -- so the
	// rewritten form is acceptable for moving to PROCEEDING state.
	for _, hdrName := range []string{"From", "To", "Call-ID", "CSeq"} {
		if v, e := req.GetHeaderValue(hdrName); e == nil {
			switch val := v.(type) {
			case string:
				resp.AddHeader(hdrName, val)
			case fmt.Stringer:
				resp.AddHeader(hdrName, val.String())
			}
		}
	}
	resp.AddHeader("Content-Length", "0")

	// Determine the caller's network address from its Via received/rport params.
	host, port, _, hopErr := p.getNextReponseHop(resp)
	if hopErr != nil {
		zap.L().Warn("sendSynthetic100Trying: cannot determine caller hop", zap.Error(hopErr))
		return
	}

	// Send on the same socket that received the original INVITE.
	if sendErr := req.ReceivedFrom.Send(host, port, resp); sendErr != nil {
		zap.L().Warn("sendSynthetic100Trying: send failed",
			zap.String("host", host), zap.Int("port", port), zap.Error(sendErr))
		return
	}
	callId, _ := req.GetCallID()
	zap.L().Info("Sent synthetic 100 Trying to INVITE caller (CALLING -> PROCEEDING)",
		zap.String("call-id", callId),
		zap.String("caller", fmt.Sprintf("%s:%d", host, port)))
}