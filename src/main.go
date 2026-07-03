package main

import (
	"fmt"
	"io"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"syscall"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
	"gopkg.in/yaml.v3"
)

type HostIp struct {
	Name string
	Ip   string
}

type ViaConfig struct {
	Address string
	// must be tcp or udp
	Protocol string
	Port     int
}
type BackendConfig struct {
	// backend address
	Address string `yaml:"address,omitempty"`
	// local bind address to sending sip message to backend
	LocalAddress string `yaml:"localAddress,omitempty"`
}
type ListenConfig struct {
	Address  string
	Via      string `yaml:"via,omitempty"`
	TcpPort  int    `yaml:"tcp-port,omitempty"`
	UdpPort  int    `yaml:"udp-port,omitempty"`
	Backends []BackendConfig
}

type RedisAddress struct {
	// Redis address in format "host:port"
	// For example: "127.0.0.1:6379"
	Address string
	// Redis password
	// If not specified, the default value is empty string
	// If the Redis server does not require a password, leave it empty
	Password string `yaml:"password,omitempty"`
	// Redis database index
	Db int `yaml:"db,omitempty"`
}

type RedisSessionStore struct {
	// Redis addresses in the cluster
	Addresses []RedisAddress
	// Redis Channel for session events updates
	// If not specified, the default value is "sipproxy:session"
	Channel string `yaml:"channel,omitempty"`

	// Redis retry timeout in seconds
	// If not specified, the default value is 5 seconds
	RetryTimeout int `yaml:"retry-timeout,omitempty"`
}

// ProxyConfig is the configuration for a RingQ SIP proxy tenant.
type ProxyConfig struct {
	Name          string
	DialogTimeout int `yaml:"dialog-timeout,omitempty"`
	// Yes or True: keep the next hop route in the route header
	// No or False: remove the next hop route in the route header
	// If not specified, the default value is "yes"
	KeepNextHopRoute string `yaml:"keep-next-hop-route,omitempty"`
	NoReceived       bool   `yaml:"no-received,omitempty"`
	// True if the route must be recorded in the route header
	// False: no record-route will be added to the header if there is any record-route in the header
	// If not specified, the route must be recorded in the route header
	MustRecordRoute   bool               `yaml:"must-record-route,omitempty"`
	RedisSessionStore *RedisSessionStore `yaml:"redis-session-store,omitempty"`
	// The listens is a list of listen configurations
	Listens []ListenConfig

	// The route is a list of destination and next hop
	// The destination is a regular expression
	Route []struct {
		Dests    []string
		Protocol string
		NextHop  string
	}
	Hosts []HostIp

	// AuthKey is the tunnel authentication key generated in the RingQ Cloud
	// portal (Tunnel Connections -> Auth Key). Injected as X-RingQ-Auth into
	// every SIP message forwarded from this proxy to the PBX so the PBX can
	// authenticate the NX Device. Required for secure deployments.
	AuthKey string `yaml:"auth-key,omitempty"`

	// DeviceID uniquely identifies this NX Device. When omitted (or empty)
	// in the YAML, startProxy derives it from /etc/machine-id at startup.
	// Sent as X-Device-ID in every outbound SIP message to the PBX.
	DeviceID string `yaml:"device-id,omitempty"`

	// PBXAPIUrl is the base URL of the RingQ PBX REST API used for
	// device binding and heartbeat (e.g. "https://customer.ringq.ai:8443").
	// The proxy appends /tunnel/bind and /tunnel/heartbeat.
	// If empty, defaults to "https://<pbx-domain>" (standard HTTPS port 443).
	PBXAPIUrl string `yaml:"pbx-api-url,omitempty"`

	// PBXDomain is the RingQ PBX SIP domain for this tenant
	// (e.g. "customer.ringq.ai"). REGISTER/INVITE To, From, and Request-URI
	// headers whose host matches PhonesDomain are rewritten to this value
	// before forwarding to the PBX so the correct tenant dialplan and
	// auth realm are resolved. Required.
	PBXDomain string `yaml:"pbx-domain"`

	// PhonesDomain is the SIP server address that LAN phones in this tenant
	// are provisioned with (e.g. the proxy's LAN IP "192.168.10.5").
	// Optional: defaults to listens[0].address when omitted.
	PhonesDomain string `yaml:"phones-domain,omitempty"`
}

type ProxiesConfigure struct {
	Admin struct {
		Addr string
	}
	Proxies []ProxyConfig
	// Global hosts IPs, used for resolving host names in the SIP messages
	Hosts []HostIp
}

// LOG_LEVEL is the global log level for the application, it can be changed dynamically through the admin API
var LOG_LEVEL = zap.NewAtomicLevel()

func init() {
	LOG_LEVEL.SetLevel(zap.DebugLevel)
}

func (vc *ViaConfig) String() string {
	return fmt.Sprintf("%s://%s:%d", vc.Protocol, vc.Address, vc.Port)
}

func initLog(logFile string, logLevel zapcore.LevelEnabler, logFormat string, logSize int, backups int) {
	var logEncoder zapcore.Encoder
	if strings.ToLower(logFormat) == "json" {
		logEncoder = zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig())
	} else {
		logEncoder = zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig())
	}

	var out io.Writer = os.Stdout
	if len(logFile) > 0 {
		out = &lumberjack.Logger{Filename: logFile,
			LocalTime:  true,
			MaxSize:    logSize,
			MaxBackups: backups}
	}

	core := zapcore.NewCore(logEncoder, zapcore.AddSync(out), logLevel)
	logger := zap.New(core)
	zap.ReplaceGlobals(logger)

}

func startProfiling(port int) {
	if port > 0 {
		go http.ListenAndServe(fmt.Sprintf(":%d", port), nil)

	}
}

func loadConfigFromReader(reader io.Reader) (*ProxiesConfigure, error) {
	r := &ProxiesConfigure{}

	decoder := yaml.NewDecoder(reader)
	err := decoder.Decode(r)

	if err != nil {
		return nil, err
	}

	return r, nil

}

func loadConfig(fileName string) (*ProxiesConfigure, error) {
	data, err := os.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("configuration file %s is empty", fileName)
	}
	// Check if the file is a valid YAML file
	p := &ProxiesConfigure{}

	err = yaml.Unmarshal(data, p)
	if err != nil {
		return nil, fmt.Errorf("failed to parse configuration file %s: %w", fileName, err)
	}
	return p, err
	/*f, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}

	defer f.Close()
	return loadConfigFromReader(f)*/

}

func toKeepNextHopRoute(s string) bool {

	possibleTrueValues := []string{"true", "yes", "1", "on", "t", "y"}

	if s == "" {
		s = os.Getenv("KEEP_NEXT_HOP_ROUTE")
	}
	return slices.Contains(possibleTrueValues, strings.ToLower(s))
}

func logLevelFromString(s string) zapcore.Level {
	level := zapcore.InfoLevel
	err := level.Set(s)
	if err != nil {
		return zapcore.InfoLevel
	}
	return level
}

func startProxies(c *cli.Context) error {
	// Initialize the logger FIRST so every subsequent error is visible.
	strLevel := c.String("log-level")
	LOG_LEVEL.SetLevel(logLevelFromString(strLevel))
	fileName := c.String("log-file")
	logSize := c.Int("log-size")
	backups := c.Int("log-backups")
	logFormat := c.String("log-format")
	profilingPort := c.Int("profiling-port")
	initLog(fileName, LOG_LEVEL, logFormat, logSize, backups)
	startProfiling(profilingPort)

	config, err := loadConfig(c.String("config"))
	if err != nil {
		zap.L().Error("Fail to load configuration file",
			zap.String("config", c.String("config")),
			zap.Error(err))
		return err
	}
	if config.Admin.Addr != "" {
		startAdminServer(config.Admin.Addr)
	}

	b, _ := yaml.Marshal(config)
	zap.L().Debug("Success load configuration file", zap.String("config", string(b)))
	// Collect all started proxies so we can send OFFLINE on shutdown.
	var activeProxies []*Proxy
	for _, proxyCfg := range config.Proxies {
		preConfigRoute := createPreConfigRoute(proxyCfg)
		resolver := createPreConfigHostResolver(config.Hosts, proxyCfg)
		zap.L().Info("start sip proxy", zap.String("name", proxyCfg.Name))
		p, err := startProxy(proxyCfg, preConfigRoute, resolver)
		if err != nil {
			zap.L().Error("Fail to start proxy",
				zap.String("name", proxyCfg.Name),
				zap.Error(err))
			return err
		}
		activeProxies = append(activeProxies, p)
	}

	// Graceful shutdown: catch SIGTERM (systemd stop) and SIGINT (Ctrl-C).
	// Send status=OFFLINE to all PBX domains before exiting so the portal
	// UI flips to OFFLINE immediately instead of waiting for last_seen timeout.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-sigCh
		zap.L().Info("Received shutdown signal -- sending OFFLINE status to PBX",
			zap.String("signal", sig.String()))

		// Fan-out: notify all proxies in parallel with a 5 s hard deadline.
		done := make(chan struct{})
		go func() {
			for _, px := range activeProxies {
				// Inline call (not goroutine) so each completes before we exit.
				px.reportTunnelStatus(TunnelStatusOffline)
			}
			close(done)
		}()
		select {
		case <-done:
			zap.L().Info("OFFLINE status sent -- shutting down")
		case <-time.After(5 * time.Second):
			zap.L().Warn("Timeout sending OFFLINE status -- shutting down anyway")
		}
		os.Exit(0)
	}()

	// Block forever (service runs until signalled).
	select {}
}

// logLevelHandler handles the HTTP requests for getting and setting the log level.
// GET /loglevel returns the current log level
// POST /loglevel?level=LEVEL sets the log level to LEVEL, where LEVEL is one of the following: Debug, Info, Warn, Error, Fatal, Panic
func logLevelHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, LOG_LEVEL.Level().String())

	case http.MethodPost:
		fallthrough
	case http.MethodPut:
		if s := r.FormValue("level"); s != "" {
			level := zapcore.InfoLevel
			err := level.Set(s)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, "invalid log level: %s", s)
			} else {
				LOG_LEVEL.SetLevel(level)
				w.WriteHeader(http.StatusOK)
				fmt.Fprintf(w, "log level set to %s", level.String())
			}
		} else {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, "missing log level")
		}
	}
}

// startAdminServer starts the admin server for health check and log level management
// The admin server listens on the specified address and provides the following endpoints:
// GET /healthz returns 200 OK if the server is healthy
// GET /loglevel returns the current log level
// POST /loglevel?level=LEVEL sets the log level to LEVEL, where LEVEL is one of the following: Debug, Info, Warn, Error, Fatal, Panic
func startAdminServer(addr string) {
	zap.L().Info("Starting admin server", zap.String("address", addr))
	httpServeMux := http.NewServeMux()
	httpServeMux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	httpServeMux.HandleFunc("/loglevel", logLevelHandler)

	go func() {
		http.ListenAndServe(addr, httpServeMux)
	}()
}

func getDefaultDialogTimeout() int {
	expire, ok := os.LookupEnv("DEFAULT_DIALOG_TIMEOUT")
	if !ok {
		return 1200
	}
	if val, err := strconv.Atoi(expire); err == nil {
		return val
	}
	return 1200
}

func startProxy(config ProxyConfig, preConfigRoute *PreConfigRoute, resolver *PreConfigHostResolver) (*Proxy, error) {
	selfLearnRoute := NewSelfLearnRoute()
	dialogTimeout := config.DialogTimeout
	if dialogTimeout <= 0 {
		dialogTimeout = getDefaultDialogTimeout()
	}

	// phonesDomain: use the configured value or derive from the first listen address.
	phonesDomain := config.PhonesDomain
	if phonesDomain == "" && len(config.Listens) > 0 {
		phonesDomain = config.Listens[0].Address
	}

	if config.PBXDomain == "" {
		zap.L().Warn("pbx-domain is not set for proxy; domain rewriting disabled",
			zap.String("proxy", config.Name))
	}

	// DeviceID: use YAML value, fall back to /etc/machine-id (first 32 hex chars).
	deviceID := config.DeviceID
	if deviceID == "" {
		deviceID = readMachineID()
	}

	if config.AuthKey == "" {
		zap.L().Warn("auth-key is not set; tunnel authentication headers will not be sent",
			zap.String("proxy", config.Name))
	} else {
		zap.L().Info("Tunnel authentication enabled",
			zap.String("device-id", deviceID))
	}

	proxy := NewProxy(config.Name,
		int64(dialogTimeout),
		config.Listens,
		toKeepNextHopRoute(config.KeepNextHopRoute),
		preConfigRoute,
		resolver,
		selfLearnRoute,
		!config.NoReceived,
		config.MustRecordRoute,
		config.RedisSessionStore,
		config.PBXDomain,
		phonesDomain,
		config.AuthKey,
		deviceID,
		config.PBXAPIUrl,
	)

	err := proxy.Start()
	if err == nil {
		zap.L().Info("Succeed to start proxy",
			zap.String("name", config.Name),
			zap.String("pbx-domain", config.PBXDomain),
			zap.String("phones-domain", phonesDomain),
			zap.String("device-id", deviceID),
			zap.String("pbx-api-url", config.PBXAPIUrl),
			zap.Bool("auth-enabled", config.AuthKey != ""))
	} else {
		zap.L().Error("Fail to start proxy", zap.String("name", config.Name))
	}
	return proxy, err
}

func createPreConfigRoute(config ProxyConfig) *PreConfigRoute {
	preConfigRoute := NewPreConfigRoute()
	for _, routeItem := range config.Route {
		for _, dest := range routeItem.Dests {
			preConfigRoute.AddRouteItem(routeItem.Protocol, dest, routeItem.NextHop)
		}

	}
	return preConfigRoute
}

func createPreConfigHostResolver(globalHostIPs []HostIp, config ProxyConfig) *PreConfigHostResolver {
	resolver := NewPreConfigHostResolver()
	for _, hostInfo := range globalHostIPs {
		resolver.AddHostIP(hostInfo.Name, hostInfo.Ip)
	}
	for _, hostInfo := range config.Hosts {
		resolver.AddHostIP(hostInfo.Name, hostInfo.Ip)
	}
	return resolver
}

func main() {
	app := &cli.App{
		Name:  "sipproxy",
		Usage: "a sip proxy in golang",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "config",
				Aliases:  []string{"c"},
				Required: true,
				Usage:    "Load configuration from `FILE`",
			},
			&cli.StringFlag{
				Name:  "log-file",
				Usage: "log file name",
			},
			&cli.StringFlag{
				Name:  "log-level",
				Usage: "one of following level: Debug, Info, Warn, Error, Fatal, Panic",
			},
			&cli.IntFlag{
				Name:  "log-size",
				Usage: "size of log file in Megabytes",
				Value: 50,
			},
			&cli.IntFlag{
				Name:  "log-backups",
				Usage: "number of log rotate files",
				Value: 10,
			},
			&cli.StringFlag{
				Name:  "log-format",
				Usage: "must be one of: json, text",
				Value: "text",
			},
			&cli.IntFlag{
				Name:  "profiling-port",
				Usage: "the profiling port number",
				Value: 0,
			},
		},
		Action: startProxies,
	}
	err := app.Run(os.Args)
	if err != nil {
		// Use fmt.Fprintf here because the zap logger may not be initialized yet
		// (e.g. config load failure happens before initLog is called).
		fmt.Fprintf(os.Stderr, "ERROR: Fail to start application: %v\n", err)
		zap.L().Error("Fail to start application", zap.String("error", err.Error()))
		os.Exit(1)
	}
}