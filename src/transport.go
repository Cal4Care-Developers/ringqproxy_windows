package main

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// RawMessage raw sip message
type RawMessage struct {
	PeerAddr        string
	PeerPort        int
	Message         *Message
	From            ServerTransport
	ReceivedSupport bool
	// TCPConn is used to send message back to the peer
	// when the message is received from TCP connection
	TcpConn net.Conn
	// the prefered backend
	Backend Backend
	Via     *ViaConfig
}

func NewRawMessage(peerAddr string, peerPort int, from ServerTransport, receivedSupport bool, msg *Message, backend Backend, via *ViaConfig) *RawMessage {
	return &RawMessage{
		PeerAddr:        peerAddr,
		PeerPort:        peerPort,
		From:            from,
		ReceivedSupport: receivedSupport,
		Message:         msg,
		TcpConn:         nil,
		Backend:         backend,
		Via:             via,
	}
}

func (rm *RawMessage) IsFromTCP() bool {
	return rm.TcpConn != nil
}

func (rm *RawMessage) GetRemoteTcpAddr() string {
	if rm.TcpConn == nil {
		return ""
	}
	return rm.TcpConn.RemoteAddr().String()
}

type MessageHandler interface {
	HandleRawMessage(msg *RawMessage)
	//HandleMessage(msg *Message, backend Backend)
}

type ServerTransport interface {
	Start(msgHandler MessageHandler) error
	// send message to remote host with port
	Send(host string, port int, message *Message) error
	// tcp, udp or tls
	GetProtocol() string

	// Get Address
	GetAddress() string

	GetPort() int

	// return True if the transport exit
	IsExit() bool
}

type SizedByteArray struct {
	b          []byte
	n          int
	msgHandler func(msg *Message)
}
type UDPServerTransport struct {
	localAddr       *net.UDPAddr
	conn            *net.UDPConn
	receivedSupport bool
	selfLearnRoute  *SelfLearnRoute
	via             *ViaConfig
	backend         Backend
	msgHandler      MessageHandler
	msgBufPool      *ByteArrayPool
	msgParseChannel chan SizedByteArray
}

type ConnectionAcceptedListener interface {
	ConnectionAccepted(conn net.Conn)
}
type TCPServerTransport struct {
	addr            string
	port            int
	conn            net.Conn
	receivedSupport bool
	selfLearnRoute  *SelfLearnRoute
	via             *ViaConfig
	// Optional backend for the transport
	backend              Backend
	msgHandler           MessageHandler
	connAcceptedListener ConnectionAcceptedListener
	exit                 bool
}

type ClientTransport interface {
	Send(msg *Message) error
	IsExpired() bool
}

type FailOverClientTransport struct {
	primary     ClientTransport
	secondaries []ClientTransport
}

type ClientTransportFactory struct {
	resolver         *PreConfigHostResolver
	clientTransports map[string]ClientTransport
}

func NewClientTransportFactory(resolver *PreConfigHostResolver) *ClientTransportFactory {
	return &ClientTransportFactory{resolver: resolver, clientTransports: make(map[string]ClientTransport)}
}

// CreateUDPClientTransport create a UDP client transport with host and port
// localAddress is the local address to bind to
func (ctf *ClientTransportFactory) CreateUDPClientTransport(host string, port int, localAddress string) (ClientTransport, error) {

	key := fmt.Sprintf("udp:%s:%d:%s", host, port, localAddress)
	if client, ok := ctf.clientTransports[key]; ok {
		return client, nil
	}

	clientTransport, err := NewUDPClientTransport(ctf.resolver, host, port, localAddress)
	if err == nil {
		ctf.clientTransports[key] = clientTransport
	}
	return clientTransport, err
}

func (ctf *ClientTransportFactory) CreateUDPClientTransportWithConn(host string, port int, conn *net.UDPConn) (ClientTransport, error) {
	key := fmt.Sprintf("udp:%s:%d:%p", host, port, conn)
	if client, ok := ctf.clientTransports[key]; ok {
		return client, nil
	}
	clientTransport, err := NewUDPClientTransportWithConn(ctf.resolver, host, port, conn)
	if err == nil {
		ctf.clientTransports[key] = clientTransport
	}
	return clientTransport, err
}

// CreateTCPClientTransport create a TCP client transport with host and port
// localAddress is the local address to be bind
func (ctf *ClientTransportFactory) CreateTCPClientTransport(host string, port int, localAddress string, connectionEstablished ConnectionEstablishedFunc) (ClientTransport, error) {
	key := fmt.Sprintf("tcp:%s:%d:%s", host, port, localAddress)
	if client, ok := ctf.clientTransports[key]; ok {
		return client, nil
	}

	clientTransport, err := NewTCPClientTransport(ctf.resolver, host, port, localAddress, connectionEstablished)
	if err == nil {
		ctf.clientTransports[key] = clientTransport
	}
	return clientTransport, err
}

// RemoveUDPClientTransport remove the UDP client transport with host and port
// localAddress is the local address to bind to
func (ctf *ClientTransportFactory) RemoveUDPClientTransport(host string, port int, localAddress string) {
	key := fmt.Sprintf("udp:%s:%d:%s", host, port, localAddress)
	delete(ctf.clientTransports, key)
}

// RemoveTCPClientTransport remove the TCP client transport with host and port
// localAddress is the local address to bind to
func (ctf *ClientTransportFactory) RemoveTCPClientTransport(host string, port int, localAddress string) {
	key := fmt.Sprintf("tcp:%s:%d:%s", host, port, localAddress)
	delete(ctf.clientTransports, key)
}

// NewFailOverClientTransport create a fail over client transport with primary and secondary
// client transport.
// BUG FIX: the original implementation ignored the secondaries parameter, always
// creating an empty slice. TCP transports are stored as secondaries (not primary),
// so this caused every TCP Send() to fail immediately with "fail to send message"
// because both primary (nil) and secondaries (empty) were absent.
func NewFailOverClientTransport(primary ClientTransport, secondaries []ClientTransport) *FailOverClientTransport {
	if secondaries == nil {
		secondaries = make([]ClientTransport, 0)
	}
	return &FailOverClientTransport{primary: primary, secondaries: secondaries}
}

// Set primary client transport
func (fct *FailOverClientTransport) SetPrimary(client ClientTransport) {
	fct.primary = client
}

// AddSecondary add the cient to back
func (fct *FailOverClientTransport) AddSecondary(client ClientTransport) {
	fct.secondaries = append(fct.secondaries, client)
}

func (fct *FailOverClientTransport) SetSecondaries(clients []ClientTransport) {
	fct.secondaries = clients
}

// Send send message to the primary client transport, if failed, send to the secondary client transport
// if both failed, return error
func (fct *FailOverClientTransport) Send(msg *Message) error {
	if fct.primary != nil {
		err := fct.primary.Send(msg)
		if err == nil {
			return nil
		}
	}
	for _, client := range fct.secondaries {
		err := client.Send(msg)
		if err == nil {
			return nil
		}
	}
	return fmt.Errorf("fail to send message")
}

// IsConnected return true if the primary or secondary client transport is connected
func (fct *FailOverClientTransport) IsConnected() bool {
	return fct.primary != nil || len(fct.secondaries) > 0
}

// IsExpired return true if the primary or secondary client transport is expired
func (fct *FailOverClientTransport) IsExpired() bool {
	if fct.primary != nil && fct.primary.IsExpired() {
		return true
	}
	for _, client := range fct.secondaries {
		if client.IsExpired() {
			return true
		}
	}
	return false
}

type UDPClientTransport struct {
	resolver *PreConfigHostResolver
	host     string
	port     int
	// if the connection is pre-connected, if true, the conn is pre-connected connection, otherwise, it is not a pre-connected connection
	preConnected bool
	// conn       is the UDP connection to send message
	conn *net.UDPConn
	// localAddr  is the local address to bind to or nil if not specified:
	// - not nil, the conn is pre-connected connection, conn.Write() should be used to send message to remote
	// - nil, the conn is not a pre-connected connection, conn.WriteToUDP() should be used to send message to remote
	localAddr *net.UDPAddr
}

type TCPClientTransport struct {
	resolver              *PreConfigHostResolver
	host                  string
	port                  string
	localAddress          string
	reconnectable         bool
	conn                  net.Conn
	expire                int64
	connectionEstablished ConnectionEstablishedFunc
}

var SupportedProtocol = map[string]string{"udp": "udp", "tcp": "tcp"}

// NewUDPClientTransport create a UDP client transport with host and port
func NewUDPClientTransport(resolver *PreConfigHostResolver, host string, port int, localAddress string) (*UDPClientTransport, error) {
	/*raddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		zap.L().Error("Fail to resolve udp host address", zap.String("host", host), zap.Int("port", port), zap.String("error", err.Error()))
		return nil, err
	}*/
	var laddr *net.UDPAddr = nil
	if len(localAddress) > 0 {
		laddr, _ = net.ResolveUDPAddr("udp", net.JoinHostPort(localAddress, "0"))
	}
	return &UDPClientTransport{resolver: resolver,
		host:         host,
		port:         port,
		preConnected: true,
		conn:         nil,
		localAddr:    laddr}, nil
}

func NewUDPClientTransportWithConn(resolver *PreConfigHostResolver, host string, port int, conn *net.UDPConn) (*UDPClientTransport, error) {
	return &UDPClientTransport{resolver: resolver,
		host:         host,
		port:         port,
		preConnected: false,
		conn:         conn,
		localAddr:    nil}, nil
}

func (u *UDPClientTransport) connect() error {
	if u.conn != nil {
		return nil
	}
	peerAddrs, err := u.getPeerAddrs()
	if err != nil {
		zap.L().Error("Fail to get remote addresses", zap.String("remoteHost", u.host), zap.Int("remotePort", u.port))
		return err
	}
	for _, peerAddr := range peerAddrs {
		conn, err := net.DialUDP("udp", u.localAddr, peerAddr)
		if err == nil {
			zap.L().Info("Succeed to make UDP connection", zap.String("localAddr", conn.LocalAddr().String()), zap.String("remoteAddr", conn.RemoteAddr().String()))
			u.conn = conn
			return nil
		}
		zap.L().Error("Fail to listen on UDP", zap.String("localAddr", u.localAddr.String()), zap.String("remoteAddr", peerAddr.String()), zap.String("error", err.Error()))
	}
	return fmt.Errorf("fail to listen on UDP" + u.localAddr.String())
}

func (u *UDPClientTransport) getPeerAddrs() ([]*net.UDPAddr, error) {
	ips, err := u.resolveHost()
	peerAddrs := make([]*net.UDPAddr, 0)
	if err != nil {
		return peerAddrs, err
	}
	for _, ip := range ips {
		parsedIp := net.ParseIP(ip)
		if parsedIp != nil {
			peerAddrs = append(peerAddrs, &net.UDPAddr{IP: parsedIp, Port: u.port})
		} else {
			zap.L().Error("Fail to parse IP for UDP client transport", zap.String("IP", ip))
		}
	}
	if len(peerAddrs) == 0 {
		return peerAddrs, fmt.Errorf("no available remote addresses")
	}
	return peerAddrs, nil
}

func (u *UDPClientTransport) resolveHost() ([]string, error) {
	if u.resolver != nil {
		return u.resolver.GetIps(u.host)
	}
	return []string{u.host}, nil
}

// Send send message to the remote address
func (u *UDPClientTransport) Send(msg *Message) error {
	err := u.connect()
	callId, _ := msg.GetCallID()
	if err != nil {
		zap.L().Error("Fail to make udp connection remote host", zap.String("remoteHost", u.host), zap.Int("remotePort", u.port), zap.Bool("request", msg.IsRequest()), zap.String("call-id", callId))
		return err
	}
	b, err := msg.Bytes()
	if err != nil {
		zap.L().Error("Fail to encode the message", zap.String("message", msg.String()))
		return err
	}
	err = u.sendData(b)
	remoteAddr := net.JoinHostPort(u.host, strconv.Itoa(u.port))
	if err == nil {
		if zap.L().Core().Enabled(zap.DebugLevel) {
			zap.L().Debug("Succeed to send message through UDP", zap.String("localAddr", u.conn.LocalAddr().String()), zap.String("remoteAddr", remoteAddr), zap.String("message", msg.String()))
		} else {
			zap.L().Info("Succeed to send message through UDP", zap.String("localAddr", u.conn.LocalAddr().String()), zap.String("remoteAddr", remoteAddr), zap.Bool("request", msg.IsRequest()), zap.String("call-id", callId))
		}
	} else {
		zap.L().Error("Fail to send message", zap.String("localAddr", u.conn.LocalAddr().String()), zap.String("remoteAddr", remoteAddr), zap.String("message", msg.String()), zap.String("error", err.Error()))
	}
	return err

}

func (u *UDPClientTransport) sendData(b []byte) error {
	if u.preConnected {
		_, err := u.conn.Write(b)
		return err
	}
	peerAddrs, err := u.getPeerAddrs()
	if err == nil {
		for _, peerAddr := range peerAddrs {
			_, err = u.conn.WriteToUDP(b, peerAddr)
			if err == nil {
				return nil
			}
		}
	}
	return fmt.Errorf("fail to send data to " + u.host + ":" + strconv.Itoa(u.port))
}

func (u *UDPClientTransport) IsExpired() bool {
	return false
}

type ClientTransportMgr struct {
	sync.Mutex
	transports             map[string]*FailOverClientTransport
	lastCleanTime          int64
	selfLearnRoute         *SelfLearnRoute
	clientTransportFactory *ClientTransportFactory
	connectionEstablished  ConnectionEstablishedFunc
}

// NewClientTransportMgr create a client transport manager object
func NewClientTransportMgr(clientTransportFactory *ClientTransportFactory,
	selfLearnRoute *SelfLearnRoute,
	connectionEstablished ConnectionEstablishedFunc) *ClientTransportMgr {

	return &ClientTransportMgr{transports: make(map[string]*FailOverClientTransport),
		lastCleanTime:          time.Now().Unix(),
		selfLearnRoute:         selfLearnRoute,
		clientTransportFactory: clientTransportFactory,
		connectionEstablished:  connectionEstablished}

}

// GetTransport Get the client ransport by the protocol, host and port
func (c *ClientTransportMgr) GetTransport(protocol string, host string, port int, transId string) (*FailOverClientTransport, error) {
	c.Lock()
	defer c.Unlock()

	c.cleanExpiredTransport()

	protocol = strings.ToLower(protocol)
	if _, ok := SupportedProtocol[protocol]; !ok {
		return nil, fmt.Errorf("not support %s", protocol)
	}
	fullAddr := c.getFullAddr(protocol, host, port, transId)

	zap.L().Info("get full address", zap.String("fullAddr", fullAddr))

	if trans, ok := c.transports[fullAddr]; ok {
		zap.L().Info("get client transport by full address", zap.String("fullAddr", fullAddr))
		return trans, nil
	}
	trans, err := c.createClientTransport(protocol, host, port)
	if err != nil {
		zap.L().Info("fail to create client transport by full address", zap.String("fullAddr", fullAddr))
		return nil, err
	}
	c.transports[fullAddr] = trans
	zap.L().Info("succeed to create client by full address", zap.String("fullAddr", fullAddr))
	return trans, nil
}

// RemoveTransport remove the client transport by the protocol, host and port
// transId is used to identify the transport
func (c *ClientTransportMgr) RemoveTransport(protocol string, host string, port int, transId string) {
	c.Lock()
	defer c.Unlock()
	protocol = strings.ToLower(protocol)
	if _, ok := SupportedProtocol[protocol]; !ok {
		return
	}
	fullAddr := c.getFullAddr(protocol, host, port, transId)

	delete(c.transports, fullAddr)
}

func (c *ClientTransportMgr) getFullAddr(protocol string, host string, port int, transId string) string {
	fullAddr := fmt.Sprintf("%s://%s", protocol, net.JoinHostPort(host, strconv.Itoa(port)))

	if protocol == "tcp" && transId != "" {
		fullAddr = fmt.Sprintf("%s-%s", fullAddr, transId)
	}

	return fullAddr
}

func (c *ClientTransportMgr) createClientTransport(protocol string, host string, port int) (*FailOverClientTransport, error) {
	var client ClientTransport = nil
	var err error = nil
	var localAddress string = c.getLocalAddress(host, protocol)

	switch protocol {
	case "udp":
		serverTransport, success := c.selfLearnRoute.GetRoute(host, protocol)
		if success && serverTransport != nil {
			if udpServerTransport, ok := serverTransport.(*UDPServerTransport); ok {
				client, err = c.clientTransportFactory.CreateUDPClientTransportWithConn(host, port, udpServerTransport.conn)
			}
		}

		if client == nil || err != nil {
			// if self learn route is available, use it to create a new UDP client transport
			// if self learn route is not available, create a new UDP client transport
			client, err = c.clientTransportFactory.CreateUDPClientTransport(host, port, localAddress)
		}
		if err == nil {
			return NewFailOverClientTransport(client, make([]ClientTransport, 0)), nil
		} else {
			return nil, err
		}
	case "tcp":
		addr := c.getFullAddr(protocol, host, port, "")
		if trans, ok := c.transports[addr]; ok {
			return NewFailOverClientTransport(nil, trans.secondaries), nil
		} else {
			client, err = c.clientTransportFactory.CreateTCPClientTransport(host, port, localAddress, c.connectionEstablished)
			if err == nil {
				c.transports[addr] = NewFailOverClientTransport(nil, []ClientTransport{client})
				return c.transports[addr], nil
			} else {
				return nil, err
			}
		}

	default:
		return nil, fmt.Errorf("not support %s", protocol)
	}

}

func (c *ClientTransportMgr) getLocalAddress(host string, protocol string) string {
	if c.selfLearnRoute != nil {
		return c.selfLearnRoute.GetRouteAddress(host, protocol)
	}
	return ""
}

func (c *ClientTransportMgr) cleanExpiredTransport() {
	var now int64 = time.Now().Unix()
	if now-c.lastCleanTime < 60 {
		return
	}
	c.lastCleanTime = now
	var expiredTransports []string = make([]string, 0)

	for key, transport := range c.transports {
		if transport.IsExpired() {
			expiredTransports = append(expiredTransports, key)
		}
	}
	for _, key := range expiredTransports {
		delete(c.transports, key)
	}

}

// NewTCPClientTransport create a TCP client transport with the specified host and port
func NewTCPClientTransport(resolver *PreConfigHostResolver, host string, port int, localAddress string, connectionEstablished ConnectionEstablishedFunc) (*TCPClientTransport, error) {
	//addr := net.JoinHostPort(host, strconv.Itoa(port))
	return &TCPClientTransport{resolver: resolver,
		host:                  host,
		port:                  strconv.Itoa(port),
		localAddress:          localAddress,
		reconnectable:         true,
		conn:                  nil,
		expire:                0,
		connectionEstablished: connectionEstablished,
	}, nil
}

func NewTCPClientTransportWithConn(conn net.Conn) (*TCPClientTransport, error) {
	zap.L().Info("create TCPClientTransportWithConn", zap.String("remoteAddr", conn.RemoteAddr().String()))
	host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())
	return &TCPClientTransport{resolver: nil,
		host:                  host,
		port:                  port,
		reconnectable:         false,
		conn:                  conn,
		expire:                time.Now().Unix() + 3600,
		connectionEstablished: nil}, nil
}

func (t *TCPClientTransport) Send(msg *Message) error {
	b, err := msg.Bytes()

	if err != nil {
		return err
	}

	callId, _ := msg.GetCallID()
	for range 2 {
		if t.conn == nil && t.reconnectable {
			if t.createConnection() != nil {
				continue
			}
		}
		if t.conn == nil {
			continue
		}
		_, err := t.conn.Write(b)
		if err == nil {
			zap.L().Info("Succeed to send message to TCP server", zap.String("host", t.host), zap.String("port", t.port), zap.Bool("request", msg.IsRequest()), zap.String("call-id", callId))
			return nil
		}
		zap.L().Warn("Fail to send message to TCP server at this time, try it again", zap.String("host", t.host), zap.String("port", t.port), zap.Bool("request", msg.IsRequest()), zap.String("call-id", callId))
		t.conn.Close()
		t.conn = nil
	}
	zap.L().Error("Fail to send message to TCP server", zap.String("host", t.host), zap.String("port", t.port), zap.Bool("request", msg.IsRequest()), zap.String("call-id", callId))
	return fmt.Errorf("fail to send message to " + t.host + ":" + t.port)
}

func (t *TCPClientTransport) createConnection() error {
	ips, err := t.resolveHost()

	if err != nil {
		return err
	}
	laddr, _ := net.ResolveTCPAddr("tcp", net.JoinHostPort(t.localAddress, "0"))
	for _, ip := range ips {
		addr := net.JoinHostPort(ip, t.port)
		raddr, err := net.ResolveTCPAddr("tcp", addr)
		if err != nil {
			zap.L().Error("Fail to resolve ip to TCP Address", zap.String("ip", ip))
			continue
		}
		zap.L().Info("Try to connect TCP server with ip", zap.String("host", t.host), zap.String("port", t.port), zap.String("hostIp", ip), zap.String("localAddress", t.localAddress))
		conn, err := net.DialTCP("tcp", laddr, raddr)
		if err != nil {
			zap.L().Error("Fail to make TCP dial to remote address", zap.String("remoteAddress", raddr.String()))
			continue
		}
		zap.L().Info("Succeed to connect tcp server", zap.String("host", t.host), zap.String("port", t.port), zap.String("hostIp", ip))
		// OS-level TCP keepalive: the OS sends keepalive probes every 30 s of
		// idle time. This prevents the Fortigate (and other NAT/firewalls) from
		// closing the TCP session due to idle-state timeout, which would
		// cause FS to lose the outbound SIP flow and fall back to unreachable
		// UDP pings.
		conn.SetKeepAlive(true)
		conn.SetKeepAlivePeriod(30 * time.Second)
		t.conn = conn
		// Start RFC 5626 SIP-level CRLF keepalive for additional robustness
		// (in case the Fortigate has SIP ALG that closes idle TCP SIP sessions).
		go t.crlfKeepaliveLoop(conn)
		if t.connectionEstablished != nil {
			t.connectionEstablished(conn)
		}
		return nil

	}
	zap.L().Error("Fail to connect tcp server", zap.String("host", t.host), zap.String("port", t.port))
	return fmt.Errorf("fail to connect tcp server " + t.host + ":" + t.port)
}
func (t *TCPClientTransport) resolveHost() ([]string, error) {
	if t.resolver != nil {
		return t.resolver.GetIps(t.host)
	}
	return []string{t.host}, nil
}
// crlfKeepaliveLoop sends RFC 5626 double-CRLF keepalive pings every 30 s
// on the TCP connection. This prevents NAT/firewall TCP session timeouts
// (e.g. Fortigate idle-timer or SIP ALG) from dropping the persistent
// proxy->PBX connection, which would make FS lose the outbound flow and
// fall back to unreachable UDP pings.
//
// FreeSWITCH responds to the double-CRLF ping with a single CRLF pong
// ("\r\n"). ParseMessage() already handles this correctly: its leading
// skipWhiteSpace() call silently consumes any \r\n bytes before the
// next real SIP start-line, so no extra handling is needed here.
func (t *TCPClientTransport) crlfKeepaliveLoop(conn net.Conn) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	ping := []byte("\r\n\r\n") // RFC 5626 section 4.4.1 double-CRLF ping
	for range ticker.C {
		if t.conn != conn {
			// This connection was replaced by a newer one; stop.
			return
		}
		if _, err := conn.Write(ping); err != nil {
			zap.L().Debug("CRLF keepalive write failed; TCP connection likely closed",
				zap.String("host", t.host), zap.String("port", t.port), zap.Error(err))
			return
		}
		zap.L().Debug("Sent RFC 5626 CRLF keepalive ping",
			zap.String("host", t.host), zap.String("port", t.port))
	}
}

func (t *TCPClientTransport) IsExpired() bool {
	return t.expire > 0 && time.Now().Unix() > t.expire
}

func NewUDPServerTransport(addr string, port int, receivedSupport bool, selfLearnRoute *SelfLearnRoute, via *ViaConfig, backend Backend) (*UDPServerTransport, error) {

	zap.L().Info("Create new UDP server transport", zap.String("addr", addr), zap.Int("port", port))
	localAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(addr, strconv.Itoa(port)))
	if err != nil {
		zap.L().Error("Not a valid ip address", zap.String("addr", addr), zap.Int("port", port))
		return nil, err
	}
	return &UDPServerTransport{
		localAddr:       localAddr,
		receivedSupport: receivedSupport,
		msgHandler:      nil,
		msgParseChannel: make(chan SizedByteArray, 40960),
		msgBufPool:      NewByteArrayPool(40960, 64*1024),
		via:             via,
		selfLearnRoute:  selfLearnRoute,
		backend:         backend,
	}, nil
}

func (u *UDPServerTransport) Send(host string, port int, msg *Message) error {
	remoteAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		zap.L().Error("Fail to resolve UDP address", zap.String("host", host), zap.Int("port", port))
		return err
	}
	b, err := msg.Bytes()
	if err != nil {
		return err
	}
	n, err := u.conn.WriteToUDP(b, remoteAddr)
	callId, _ := msg.GetCallID()
	if err == nil {
		zap.L().Info("Succeed to send message through UDP", zap.Int("length", n), zap.String("localAddr", u.conn.LocalAddr().String()), zap.String("remoteAddress", remoteAddr.String()), zap.String("call-id", callId))
	} else {
		zap.L().Error("Fail to send message", zap.String("localAddr", u.localAddr.String()), zap.String("remoteAddress", remoteAddr.String()), zap.String("call-id", callId), zap.String("error", err.Error()))
	}
	return err
}

func (u *UDPServerTransport) Start(msgHandler MessageHandler) error {
	u.msgHandler = msgHandler
	conn, err := net.ListenUDP("udp", u.localAddr)
	if err != nil {
		zap.L().Error("Fail to listen on UDP", zap.String("localAddr", u.localAddr.String()))
		return err
	}
	u.conn = conn
	zap.L().Info("Success to listen on UDP", zap.String("localAddr", u.localAddr.String()))
	go u.startParseMessage()
	go u.receiveMessage()
	return nil
}

func (u *UDPServerTransport) receiveMessage() {
	for {
		buf := u.msgBufPool.Alloc()
		n, peerAddr, err := u.conn.ReadFromUDP(buf)
		if err != nil {
			zap.L().Error("Fail to read data", zap.String("localAddr", u.localAddr.String()), zap.String("error", err.Error()))
			break
		}
		address := peerAddr.IP.String()
		port := peerAddr.Port
		zap.L().Info("a UDP packet is received", zap.Int("length", n), zap.String("localAddr", u.localAddr.String()), zap.String("remoteAddr", peerAddr.String()))
		u.msgParseChannel <- SizedByteArray{b: buf, n: n, msgHandler: func(msg *Message) {
			u.msgHandler.HandleRawMessage(NewRawMessage(address, port, u, u.receivedSupport, msg, u.backend, u.via))
		}}

	}
}

func (u *UDPServerTransport) startParseMessage() {
	for {
		sized_byte_array := <-u.msgParseChannel
		// Slice to [:n] so the reader only sees the bytes in this UDP
		// packet, not stale data from a previous message in the reused
		// buffer.  Without this, a 2- or 4-byte keepalive arriving after a
		// large SIP message causes the parser to read the old message's
		// tail bytes and produce phantom methods like "TE", "EL", "STER",
		// "CRIBE" -- the second half of INVITE, CANCEL, REGISTER, SUBSCRIBE.
		reader := bufio.NewReaderSize(bytes.NewBuffer(sized_byte_array.b[:sized_byte_array.n]), sized_byte_array.n)
		msg, err := ParseMessage(reader)
		u.msgBufPool.Free(sized_byte_array.b)
		if err == nil {
			sized_byte_array.msgHandler(msg)
		}
	}
}

func (u *UDPServerTransport) GetProtocol() string {
	return "udp"
}

func (u *UDPServerTransport) GetAddress() string {
	host, _, _ := net.SplitHostPort(u.localAddr.String())
	return host
}

func (u *UDPServerTransport) GetPort() int {
	_, port, _ := net.SplitHostPort(u.localAddr.String())
	i, _ := strconv.Atoi(port)
	return i
}

func (u *UDPServerTransport) IsExit() bool {
	return false
}

func NewTCPServerTransport(addr string,
	port int,
	receivedSupport bool,
	connAcceptedListener ConnectionAcceptedListener,
	selfLearnRoute *SelfLearnRoute,
	via *ViaConfig,
	backend Backend) *TCPServerTransport {
	return &TCPServerTransport{addr: addr,
		port:                 port,
		conn:                 nil,
		receivedSupport:      receivedSupport,
		connAcceptedListener: connAcceptedListener,
		selfLearnRoute:       selfLearnRoute,
		via:                  via,
		backend:              backend,
		msgHandler:           nil,
		exit:                 false,
	}
}

func NewTCPServerTransportWithConn(conn net.Conn,
	receivedSupport bool,
	selfLearnRoute *SelfLearnRoute,
	backend Backend) *TCPServerTransport {
	addr, port, err := net.SplitHostPort(conn.LocalAddr().String())

	if err == nil {
		port_i, _ := strconv.Atoi(port)
		zap.L().Info("Create new TCP server transport", zap.String("remoteAddr", conn.RemoteAddr().String()), zap.String("localAddr", conn.LocalAddr().String()))
		return &TCPServerTransport{addr: addr,
			port:                 port_i,
			conn:                 conn,
			receivedSupport:      receivedSupport,
			connAcceptedListener: nil,
			selfLearnRoute:       selfLearnRoute,
			backend:              backend,
			msgHandler:           nil,
			exit:                 false,
		}
	}
	return nil

}

func (t *TCPServerTransport) Start(msgHandler MessageHandler) error {
	t.msgHandler = msgHandler
	if t.conn == nil {
		hostPort := net.JoinHostPort(t.addr, strconv.Itoa(t.port))
		ln, err := net.Listen("tcp", hostPort)
		if err != nil {
			zap.L().Error("Fail to listen", zap.String("hostPort", hostPort))
			return err
		}
		zap.L().Info("Succeed to listen on TCP", zap.String("hostPort", hostPort))
		go t.acceptConnection(ln)
	} else {
		go t.receiveMessage(t.conn)
	}
	return nil
}

func (t *TCPServerTransport) acceptConnection(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err == nil {
			zap.L().Info("Accept a connection", zap.String("localAddr", ln.Addr().String()), zap.String("remoteAddr", conn.RemoteAddr().String()))
			t.connAcceptedListener.ConnectionAccepted(conn)
			go t.receiveMessage(conn)
		} else {
			zap.L().Error("Fail to accept client connection", zap.String("localAddr", ln.Addr().String()), zap.String("error", err.Error()))
			break
		}
	}

}

func (t *TCPServerTransport) receiveMessage(conn net.Conn) {
	reader := bufio.NewReader(conn)
	peerAddr, remotePort, _ := net.SplitHostPort(conn.RemoteAddr().String())
	peerPort, _ := strconv.Atoi(remotePort)
	localAddr, localPort, _ := net.SplitHostPort(conn.LocalAddr().String())
	zap.L().Info("start to receive sip message from tcp", zap.String("peerAddr", peerAddr), zap.String("peerPort", remotePort), zap.String("localAddr", localAddr), zap.String("localPort", localPort))
	for {
		// RFC 5626 4.4.1 skip CRLF keepalive bytes before attempting to
		// parse a SIP message.
		//
		// When the proxy sends \r\n\r\n as a ping, FS responds with \r\n.
		// Without this guard, ParseMessage receives those bare CR/LF bytes,
		// returns an error, and the loop calls conn.Close() silently
		// killing the TCP/6010 session.  The next Options ping from FS
		// (fired ~5 s later) finds no one reading, times out after 32 s,
		// and the registration is marked Unreachable and expired.
		//
		// This happened every ~30 s (the crlfKeepaliveLoop interval):
		//   13:05:48 last good Options 200 OK
		//   13:06:00 proxy sends \r\n\r\n; FS replies \r\n
		//   13:06:00 ParseMessage("\r\n") ? error ? conn.Close()
		//   13:06:05 FS Options ? no response ? 408 ? Unreachable
		//
		// Fix: peek at the stream; if the first byte is CR or LF, consume
		// all contiguous CR/LF bytes and loop back for the next real message.
		if first, peekErr := reader.Peek(1); peekErr == nil && (first[0] == '\r' || first[0] == '\n') {
			// Drain all leading CR/LF bytes (ping is \r\n\r\n, pong is \r\n).
			for {
				next, err := reader.Peek(1)
				if err != nil || (next[0] != '\r' && next[0] != '\n') {
					break
				}
				reader.ReadByte() //nolint:errcheck
			}
			zap.L().Debug("Discarded RFC 5626 CRLF keepalive bytes from TCP stream",
				zap.String("peerAddr", peerAddr), zap.String("peerPort", remotePort))
			continue
		}

		msg, err := ParseMessage(reader)
		if err != nil {
			conn.Close()
			if err.Error() == "EOF" {
				zap.L().Info("Connection closed", zap.String("peerAddr", peerAddr), zap.String("peerPort", remotePort), zap.String("localAddr", localAddr), zap.String("localPort", localPort))
			} else {
				zap.L().Error("Fail to parse message", zap.String("peerAddr", peerAddr), zap.String("peerPort", remotePort), zap.String("localAddr", localAddr), zap.String("localPort", localPort), zap.String("error", err.Error()))
			}
			break
		}
		msg.ReceivedFrom = t
		rawMsg := NewRawMessage(peerAddr, peerPort, t, t.receivedSupport, msg, t.backend, t.via)
		rawMsg.TcpConn = conn
		t.msgHandler.HandleRawMessage(rawMsg)
	}
	if t.conn != nil {
		t.exit = true
	}
}

func (t *TCPServerTransport) Send(host string, port int, message *Message) error {
	// For connection-specific transports (NewTCPServerTransportWithConn),
	// t.conn is the actual net.Conn.  Write the message directly so that
	// responses to OPTIONS / REGISTER etc. go back on the exact TCP
	// session that delivered the request, with no clientTransMgr lookup.
	//
	// For the listening server (NewTCPServerTransport), t.conn is nil;
	// those transports do not send replies directly (accepted connections
	// spawn their own TCPServerTransportWithConn instances).
	if t.conn != nil {
		b, err := message.Bytes()
		if err != nil {
			return err
		}
		_, err = t.conn.Write(b)
		return err
	}
	return nil
}

func (t *TCPServerTransport) GetProtocol() string {
	return "tcp"
}

func (t *TCPServerTransport) GetAddress() string {
	return t.addr
}

func (t *TCPServerTransport) GetPort() int {
	return t.port
}

func (u *TCPServerTransport) IsExit() bool {
	return u.conn != nil && u.exit
}