package config

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/DataDog/datadog-go/statsd"
	"go.mongodb.org/mongo-driver/event"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/x/mongo/driver/connstring"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/coinbase/mongobetween/mongo"
	"github.com/coinbase/mongobetween/proxy"
	"github.com/coinbase/mongobetween/util"
)

const usernamePlaceholder = "_"

var validNetworks = []string{"tcp", "tcp4", "tcp6", "unix", "unixpacket"}

var newStatsdClientInit = newStatsdClient

type Config struct {
	network    string
	unlink     bool
	ping       bool
	pretty     bool
	clients    []client
	level      zapcore.Level
	dynamic    string
	statsdaddr string
	logger     *zap.Logger
	statsd     *statsd.Client
	filter     *proxy.Filter
	auth       *proxy.AuthConfig
}

type client struct {
	address string
	label   string
	opts    *options.ClientOptions
}

func ParseFlags() *Config {
	config, err := parseFlags()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		flag.Usage()
		os.Exit(2)
	}
	return config
}

func (c *Config) LogLevel() zapcore.Level {
	return c.level
}

func (c *Config) Pretty() bool {
	return c.pretty
}

func (c *Config) Logger() *zap.Logger {
	return c.logger
}

func (c *Config) Statsd() *statsd.Client {
	return c.statsd
}

func (c *Config) Proxies(log *zap.Logger) (proxies []*proxy.Proxy, err error) {
	d, err := proxy.NewDynamic(c.dynamic, log)
	if err != nil {
		return nil, err
	}

	mongos := make(map[string]*mongo.Mongo)
	for _, client := range c.clients {
		m, err := mongo.Connect(log, c.statsd, client.opts, c.ping)
		if err != nil {
			return nil, err
		}
		mongos[client.address] = m
	}
	mongoLookup := func(address string) *mongo.Mongo {
		return mongos[address]
	}

	for _, client := range c.clients {
		p, err := proxy.NewProxy(log, c.statsd, client.label, c.network, client.address, c.unlink, mongoLookup, d, c.filter, c.auth)
		if err != nil {
			return nil, err
		}
		proxies = append(proxies, p)
	}
	return
}

func validNetwork(network string) bool {
	for _, n := range validNetworks {
		if n == network {
			return true
		}
	}
	return false
}

func parseFlags() (*Config, error) {
	flag.Usage = func() {
		fmt.Printf("Usage: %s [OPTIONS] address1=uri1 [address2=uri2] ...\n", os.Args[0])
		fmt.Printf("\nAll options can be set via environment variables with MONGOBETWEEN_ prefix.\n")
		fmt.Printf("Addresses can also be set via MONGOBETWEEN_ADDRESSES env var (pipe or newline separated).\n\n")
		flag.PrintDefaults()
	}

	var unlink, ping, pretty, enableSdamMetrics, enableSdamLogging bool
	var network, username, password, stats, loglevel, dynamic string
	var allowedOps, deniedOps, allowedDbs, deniedDbs, allowedColls, deniedColls string
	var allowedCollsFile string
	var proxyAuthUsers string
	flag.StringVar(&network, "network", getEnvString("network", "tcp4"), "One of: tcp, tcp4, tcp6, unix or unixpacket (env: MONGOBETWEEN_NETWORK)")
	flag.StringVar(&username, "username", getEnvString("username", ""), "MongoDB username (env: MONGOBETWEEN_USERNAME)")
	flag.StringVar(&password, "password", getEnvString("password", ""), "MongoDB password (env: MONGOBETWEEN_PASSWORD)")
	flag.StringVar(&stats, "statsd", getEnvString("statsd", ""), "Statsd address, empty to disable (env: MONGOBETWEEN_STATSD)")
	flag.BoolVar(&unlink, "unlink", getEnvBool("unlink", false), "Unlink existing unix sockets before listening (env: MONGOBETWEEN_UNLINK)")
	flag.BoolVar(&ping, "ping", getEnvBool("ping", false), "Ping downstream MongoDB before listening (env: MONGOBETWEEN_PING)")
	flag.BoolVar(&pretty, "pretty", getEnvBool("pretty", false), "Pretty print logging (env: MONGOBETWEEN_PRETTY)")
	flag.StringVar(&loglevel, "loglevel", getEnvString("loglevel", "info"), "One of: debug, info, warn, error, dpanic, panic, fatal (env: MONGOBETWEEN_LOGLEVEL)")
	flag.StringVar(&dynamic, "dynamic", getEnvString("dynamic", ""), "File or URL to query for dynamic configuration (env: MONGOBETWEEN_DYNAMIC)")
	flag.BoolVar(&enableSdamMetrics, "enable-sdam-metrics", getEnvBool("enable-sdam-metrics", false), "Enable SDAM(Server Discovery And Monitoring) metrics (env: MONGOBETWEEN_ENABLE_SDAM_METRICS)")
	flag.BoolVar(&enableSdamLogging, "enable-sdam-logging", getEnvBool("enable-sdam-logging", false), "Enable SDAM(Server Discovery And Monitoring) logging (env: MONGOBETWEEN_ENABLE_SDAM_LOGGING)")
	flag.StringVar(&allowedOps, "allowed-operations", getEnvString("allowed-operations", ""), "Comma-separated list of allowed MongoDB operations (e.g., find,insert,update) (env: MONGOBETWEEN_ALLOWED_OPERATIONS)")
	flag.StringVar(&deniedOps, "denied-operations", getEnvString("denied-operations", ""), "Comma-separated list of denied MongoDB operations (e.g., drop,dropDatabase) (env: MONGOBETWEEN_DENIED_OPERATIONS)")
	flag.StringVar(&allowedDbs, "allowed-databases", getEnvString("allowed-databases", ""), "Comma-separated list of allowed databases (e.g., app_db,logs) (env: MONGOBETWEEN_ALLOWED_DATABASES)")
	flag.StringVar(&deniedDbs, "denied-databases", getEnvString("denied-databases", ""), "Comma-separated list of denied databases (e.g., admin,config) (env: MONGOBETWEEN_DENIED_DATABASES)")
	flag.StringVar(&allowedColls, "allowed-collections", getEnvString("allowed-collections", ""), "Comma-separated list of allowed collections in db.collection format (e.g., app_db.users,app_db.orders) (env: MONGOBETWEEN_ALLOWED_COLLECTIONS)")
	flag.StringVar(&allowedCollsFile, "allowed-collections-file", getEnvString("allowed-collections-file", ""), "Path to file containing allowed collections, one per line in db.collection format (env: MONGOBETWEEN_ALLOWED_COLLECTIONS_FILE)")
	flag.StringVar(&deniedColls, "denied-collections", getEnvString("denied-collections", ""), "Comma-separated list of denied collections in db.collection format (e.g., app_db.sensitive) (env: MONGOBETWEEN_DENIED_COLLECTIONS)")
	flag.StringVar(&proxyAuthUsers, "proxy-auth", getEnvString("proxy-auth", ""), "Proxy authentication users in format user1:pass1,user2:pass2 (enables SCRAM-SHA-256 auth) (env: MONGOBETWEEN_PROXY_AUTH)")

	flag.Parse()

	network = expandEnv(network)
	username = expandEnv(username)
	password = expandEnv(password)
	stats = expandEnv(stats)
	loglevel = expandEnv(loglevel)
	dynamic = expandEnv(dynamic)
	allowedOps = expandEnv(allowedOps)
	deniedOps = expandEnv(deniedOps)
	allowedDbs = expandEnv(allowedDbs)
	deniedDbs = expandEnv(deniedDbs)
	allowedColls = expandEnv(allowedColls)
	allowedCollsFile = expandEnv(allowedCollsFile)
	deniedColls = expandEnv(deniedColls)
	proxyAuthUsers = expandEnv(proxyAuthUsers)

	level := zap.InfoLevel
	if loglevel != "" {
		err := level.Set(loglevel)
		if err != nil {
			return nil, fmt.Errorf("invalid loglevel: %s", loglevel)
		}
	}

	if !validNetwork(network) {
		return nil, fmt.Errorf("invalid network: %s", network)
	}

	addressMap := make(map[string]string)

	// Helper function to parse address=uri pairs
	parseAddresses := func(input string) error {
		input = expandEnv(input)
		all := strings.FieldsFunc(input, func(r rune) bool {
			return r == '|' || r == '\n'
		})
		for _, v := range all {
			v = strings.TrimSpace(v)
			if v == "" {
				continue
			}
			split := strings.SplitN(v, "=", 2)
			if len(split) != 2 {
				return errors.New("malformed address=uri option")
			}
			if _, ok := addressMap[split[0]]; ok {
				return fmt.Errorf("uri already defined for address: %s", split[0])
			}
			addressMap[split[0]] = split[1]
		}
		return nil
	}

	// Parse addresses from MONGOBETWEEN_ADDRESSES environment variable
	if envAddresses := os.Getenv("MONGOBETWEEN_ADDRESSES"); envAddresses != "" {
		if err := parseAddresses(envAddresses); err != nil {
			return nil, err
		}
	}

	// Parse addresses from command line arguments (these override env vars)
	for _, arg := range flag.Args() {
		if err := parseAddresses(arg); err != nil {
			return nil, err
		}
	}

	if len(addressMap) == 0 {
		return nil, errors.New("missing address=uri(s) (set via command line or MONGOBETWEEN_ADDRESSES env var)")
	}

	loggerClient := newLogger(level, pretty)
	statsdClient, err := newStatsdClientInit(stats)
	if err != nil {
		return nil, err
	}

	var clients []client
	for address, uri := range addressMap {
		label, opts, err := clientOptions(uri, username, password)
		if err != nil {
			return nil, err
		}
		initMonitoring(opts, statsdClient, loggerClient, enableSdamMetrics, enableSdamLogging)
		clients = append(clients, client{
			address: address,
			label:   label,
			opts:    opts,
		})
	}

	// Parse allowed collections from file if specified
	fileColls, err := parseFileLines(allowedCollsFile)
	if err != nil {
		return nil, err
	}

	// Merge comma-separated and file-based allowed collections
	allAllowedColls := parseCommaSeparated(allowedColls)
	allAllowedColls = append(allAllowedColls, fileColls...)

	filter := proxy.NewFilter(
		parseCommaSeparated(allowedOps),
		parseCommaSeparated(deniedOps),
		parseCommaSeparated(allowedDbs),
		parseCommaSeparated(deniedDbs),
		allAllowedColls,
		parseCommaSeparated(deniedColls),
	)

	auth, err := parseProxyAuth(proxyAuthUsers)
	if err != nil {
		return nil, err
	}

	return &Config{
		network:    network,
		unlink:     unlink,
		ping:       ping,
		pretty:     pretty,
		statsdaddr: stats,
		clients:    clients,
		level:      level,
		dynamic:    dynamic,
		logger:     loggerClient,
		statsd:     statsdClient,
		filter:     filter,
		auth:       auth,
	}, nil
}

func parseProxyAuth(users string) (*proxy.AuthConfig, error) {
	auth := proxy.NewAuthConfig()
	if users == "" {
		return auth, nil
	}

	pairs := strings.Split(users, ",")
	for _, pair := range pairs {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		parts := strings.SplitN(pair, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid proxy-auth format: %s (expected user:pass)", pair)
		}
		username := strings.TrimSpace(parts[0])
		password := strings.TrimSpace(parts[1])
		if username == "" || password == "" {
			return nil, fmt.Errorf("invalid proxy-auth: username and password cannot be empty")
		}
		if err := auth.AddUser(username, password); err != nil {
			return nil, fmt.Errorf("failed to add proxy user %s: %w", username, err)
		}
	}

	return auth, nil
}

func parseCommaSeparated(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

func parseFileLines(filePath string) ([]string, error) {
	if filePath == "" {
		return nil, nil
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filePath, err)
	}
	lines := strings.Split(string(data), "\n")
	result := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			result = append(result, line)
		}
	}
	return result, nil
}

func expandEnv(config string) string {
	// more restrictive version of os.ExpandEnv that only replaces exact matches of ${ENV}
	return regexp.MustCompile(`\${(\w+)}`).ReplaceAllStringFunc(config, func(s string) string {
		return os.ExpandEnv(s)
	})
}

// envPrefix is the prefix for all mongobetween environment variables
const envPrefix = "MONGOBETWEEN_"

// flagNameToEnvName converts a flag name to its corresponding environment variable name
// e.g., "allowed-collections" -> "MONGOBETWEEN_ALLOWED_COLLECTIONS"
func flagNameToEnvName(flagName string) string {
	return envPrefix + strings.ToUpper(strings.ReplaceAll(flagName, "-", "_"))
}

// getEnvString returns the environment variable value for a flag, or the default if not set
func getEnvString(flagName, defaultVal string) string {
	envName := flagNameToEnvName(flagName)
	if val, ok := os.LookupEnv(envName); ok {
		return val
	}
	return defaultVal
}

// getEnvBool returns the environment variable value as a bool for a flag, or the default if not set
func getEnvBool(flagName string, defaultVal bool) bool {
	envName := flagNameToEnvName(flagName)
	if val, ok := os.LookupEnv(envName); ok {
		switch strings.ToLower(val) {
		case "true", "1", "yes", "on":
			return true
		case "false", "0", "no", "off":
			return false
		}
	}
	return defaultVal
}

func clientOptions(uri, username, password string) (string, *options.ClientOptions, error) {
	uri = uriWorkaround(uri, username)

	cs, err := connstring.Parse(uri)
	if err != nil {
		return "", nil, err
	}

	label := ""
	if len(cs.UnknownOptions["label"]) > 0 {
		label = cs.UnknownOptions["label"][0]
	}

	opts := options.Client()
	opts.ApplyURI(uri)

	if username != "" {
		if opts.Auth == nil {
			opts.SetAuth(options.Credential{Username: username})
		} else if opts.Auth.Username == "" || opts.Auth.Username == usernamePlaceholder {
			opts.Auth.Username = username
		}
	}

	if password != "" {
		if opts.Auth == nil {
			opts.SetAuth(options.Credential{Password: password})
		} else if opts.Auth.Password == "" {
			opts.Auth.Password = password
		}
	}

	if err := opts.Validate(); err != nil {
		return "", nil, err
	}

	return label, opts, nil
}

func initMonitoring(opts *options.ClientOptions, statsd *statsd.Client, logger *zap.Logger, enableSdamMetrics bool, enableSdamLogging bool) *options.ClientOptions {
	// set up monitors for Pool and Server(SDAM)
	opts = opts.SetPoolMonitor(poolMonitor(statsd))
	opts = opts.SetServerMonitor(serverMonitoring(logger, statsd, enableSdamMetrics, enableSdamLogging))
	return opts
}

func uriWorkaround(uri, username string) string {
	// Workaround for a feature in the Mongo driver URI parsing where you can't set a URI
	// without setting the username ("error parsing uri: authsource without username is
	// invalid"). This method force-adds a username in the URI, which can be overridden
	// using SetAuth(). This workaround can be removed once the 1.4 driver is released
	// (see https://jira.mongodb.org/browse/GODRIVER-1473).
	if !strings.Contains(uri, "@") && username != "" {
		split := strings.SplitN(uri, "//", 2)
		if len(split) == 2 {
			uri = fmt.Sprintf("%s//%s@%s", split[0], usernamePlaceholder, split[1])
		} else {
			uri = fmt.Sprintf("%s@%s", usernamePlaceholder, split[0])
		}
	}
	return uri
}

func newStatsdClient(statsAddress string) (*statsd.Client, error) {
	if statsAddress == "" {
		return nil, nil
	}
	return statsd.New(statsAddress, statsd.WithNamespace("mongobetween"))
}

func newLogger(level zapcore.Level, pretty bool) *zap.Logger {
	var c zap.Config
	if pretty {
		c = zap.NewDevelopmentConfig()
		c.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	} else {
		c = zap.NewProductionConfig()
	}

	c.EncoderConfig.MessageKey = "message"
	c.Level.SetLevel(level)

	log, err := c.Build(zap.AddStacktrace(zap.FatalLevel))
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}

	return log
}

func poolMonitor(sd *statsd.Client) *event.PoolMonitor {
	if sd == nil {
		return nil
	}
	checkedOut, checkedIn := util.StatsdBackgroundGauge(sd, "pool.checked_out_connections", []string{})
	opened, closed := util.StatsdBackgroundGauge(sd, "pool.open_connections", []string{})

	return &event.PoolMonitor{
		Event: func(e *event.PoolEvent) {
			snake := strings.ToLower(regexp.MustCompile("([a-z0-9])([A-Z])").ReplaceAllString(e.Type, "${1}_${2}"))
			name := fmt.Sprintf("pool_event.%s", snake)
			tags := []string{
				fmt.Sprintf("address:%s", e.Address),
				fmt.Sprintf("reason:%s", e.Reason),
			}
			switch e.Type {
			case event.ConnectionCreated:
				opened(name, tags)
			case event.ConnectionClosed:
				closed(name, tags)
			case event.GetSucceeded:
				checkedOut(name, tags)
			case event.ConnectionReturned:
				checkedIn(name, tags)
			default:
				_ = sd.Incr(name, tags, 1)
			}
		},
	}
}

func serverMonitoring(log *zap.Logger, statsdClient *statsd.Client, enableSdamMetrics bool, enableSdamLogging bool) *event.ServerMonitor {
	// Disable SDAM metrics if statsd client is nil
	if statsdClient == nil {
		enableSdamMetrics = false
	}

	return &event.ServerMonitor{
		ServerOpening: func(e *event.ServerOpeningEvent) {
			if enableSdamMetrics {
				_ = statsdClient.Incr("server_opening_event",
					[]string{
						fmt.Sprintf("address:%s", e.Address),
						fmt.Sprintf("topology_id:%s", e.TopologyID.Hex()),
					}, 0)
			}
		},

		ServerClosed: func(e *event.ServerClosedEvent) {
			if enableSdamMetrics {
				_ = statsdClient.Incr("server_closed_event",
					[]string{
						fmt.Sprintf("address:%s", e.Address),
						fmt.Sprintf("topology_id:%s", e.TopologyID.Hex()),
					}, 0)
			}
		},

		ServerDescriptionChanged: func(e *event.ServerDescriptionChangedEvent) {
			if enableSdamMetrics {
				_ = statsdClient.Incr("server_description_changed_event",
					[]string{
						fmt.Sprintf("address:%s", e.Address),
						fmt.Sprintf("topology_id:%s", e.TopologyID.Hex()),
					}, 0)
			}

			if enableSdamLogging {
				var prevDMap map[string]interface{}
				var newDMap map[string]interface{}

				prevDescription, _ := json.Marshal(&e.PreviousDescription)
				_ = json.Unmarshal(prevDescription, &prevDMap)
				newDescription, _ := json.Marshal(e.NewDescription)
				_ = json.Unmarshal(newDescription, &newDMap)

				log.Info("ServerDescriptionChangedEvent detected. ",
					zap.Any("address", e.Address),
					zap.String("topologyId", e.TopologyID.Hex()),
					zap.Any("prevDescription", prevDMap),
					zap.Any("newDescription", newDMap),
				)
			}
		},

		TopologyDescriptionChanged: func(e *event.TopologyDescriptionChangedEvent) {
			if enableSdamMetrics {
				_ = statsdClient.Incr("topology_description_changed_event",
					[]string{
						fmt.Sprintf("topology_id:%s", e.TopologyID.Hex()),
					}, 0)
			}
			if enableSdamLogging {
				var prevDMap map[string]interface{}
				var newDMap map[string]interface{}

				prevDescription, _ := json.Marshal(&e.PreviousDescription)
				_ = json.Unmarshal(prevDescription, &prevDMap)
				newDescription, _ := json.Marshal(e.NewDescription)
				_ = json.Unmarshal(newDescription, &newDMap)

				log.Info("TopologyDescriptionChangedEvent detected. ",
					zap.String("topologyId", e.TopologyID.Hex()),
					zap.Any("prevDescription", prevDMap),
					zap.Any("newDescription", newDMap),
				)
			}
		},

		TopologyOpening: func(e *event.TopologyOpeningEvent) {
			if enableSdamMetrics {
				_ = statsdClient.Incr("topology_opening_event",
					[]string{
						fmt.Sprintf("topology_id:%s", e.TopologyID.Hex()),
					}, 0)
			}
		},

		TopologyClosed: func(e *event.TopologyClosedEvent) {
			if enableSdamMetrics {
				_ = statsdClient.Incr("topology_closed_event",
					[]string{
						fmt.Sprintf("topology_id:%s", e.TopologyID.Hex()),
					}, 0)
			}
		},
	}
}
