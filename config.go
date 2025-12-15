package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"net/netip"
	"path/filepath"
	"os"
	"os/signal"
	"sync"
	"strings"
	"syscall"
)

var BUILD_NAME = "h3tunnel"
var BUILD_VERSION = "unknown"
var BUILD_DATE = "unkown"

var MASQUE_PATH = "/.well-known/masque/ip/*/*/"

var wg sync.WaitGroup

var cfg struct {
	done chan os.Signal
	debug bool
	log_prefix string
	benchmark bool
	config_file string
	users_file string

	port int

	dev string
	mtu int
	netns string

	tls_ca string
	tls_cert string
	tls_key string

	listen string
	ippool string
	max_pool_size int
	addroutes string
	client_auth bool

	hostname string
	iprequest string
	username string
	password string

	users map[string][]byte
	local_ip netip.Prefix
	routes[] netip.Prefix
}

func setup_signals() {
	cfg.done = make(chan os.Signal, 1)
	signal.Notify(cfg.done, syscall.SIGINT, syscall.SIGTERM)
}

func read_stdin(prompt string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%s: ", prompt)
	text, err := reader.ReadString('\n')
	if err != nil {
		panic("Failed to read from stdin "+err.Error())
	}
	return strings.TrimSpace(text)
}

func read_config(cfgfile string, create bool) map[string]string {
	data := map[string]string{}

	f, err := os.Open(cfgfile)
	if err != nil {
		if create {
			log_err("Cant open configuration file %s, creating default one", cfgfile)
			write_config(cfgfile)
		}
		return data
	}

	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "#") { continue }
		options := strings.SplitN(scanner.Text(), ":", 2)
		if len(options) != 2 { continue }
		key := strings.TrimSpace(options[0])
		value := strings.TrimSpace(options[1])
		if len(key) == 0 { continue }
		if len(value) == 0 { continue }
		data[key] = value
	}
	f.Close()

	return data
}

func write_config(cfgfile string) {
	f, err := os.Create(cfgfile)
	if err != nil { panic(err) }

	header := fmt.Sprintf("# Configuration for %s %s (%s %s)\n\n", BUILD_NAME, BUILD_TYPE, BUILD_VERSION, BUILD_DATE)
	f.WriteString(header)

	flag.VisitAll(func(i *flag.Flag) {
		if i.Name == "config_file" { return }
		prefix := ""
		if len(i.Value.String()) == 0 { prefix = "# " }

		line := fmt.Sprintf("### %s\n%s%s: %s\n\n", i.Usage, prefix, i.Name, i.Value.String())
		f.WriteString(line)
	})
	f.Close()
}

func authenticate(username, password string) bool {
	local_password, ok := cfg.users[username]
	remote_password := sha256.Sum256([]byte(password))

	// burn same CPU time for valid and invalid user
	if ok {
		ok = (subtle.ConstantTimeCompare(local_password[:], remote_password[:]) == 1)
	} else {
		ok = (subtle.ConstantTimeCompare(remote_password[:], remote_password[:]) != 1)
	}

	return ok
}

func get_random_password(length int) string {
	random := make([]byte, length)
	_, err := rand.Read(random)
	if err != nil { panic(err) }

	pass := base64.StdEncoding.EncodeToString(random)
	pass = strings.Replace(pass, "/", "", -1)
	pass = strings.Replace(pass, "+", "", -1)
	pass = strings.Replace(pass, "=", "", -1)

	if len(pass) > length { return pass[:length] }
	return pass
}

func get_hashed_password(password string) []byte {
	if len(password) == 64 {
		data, err := hex.DecodeString(password)
		if err == nil { return data }
	}

	data := sha256.Sum256([]byte(password))
	return data[:]
}

func load_userdb(filename string) {
	cfg.users = make(map[string][]byte)
	for user, pass := range read_config(filename, false) {
		cfg.users[user] = get_hashed_password(pass)
	}

	if len(cfg.users) > 0 {
		log_info("Found %d users in local database", len(cfg.users))
		return
	}

	// generate temporary demo user with random passwort
	pass := get_random_password(10)
	cfg.users["demo"] = get_hashed_password(pass)
	log_err("Generated user demo with password %s", pass)
}

func get_file_config(filename string) {
	config := read_config(filename, true)
	for key, _ := range config {
		flag.Visit(func(i *flag.Flag) {
			if i.Name != key { return }
			log_info("Configuration %s overriden by command line argument", key)
			delete(config, key)
		})
	}

	for key, option := range config {
		flag.Set(key, option)
	}
}

func get_config() {
	filename := filepath.Base(os.Args[0])

	flag.BoolVar(&cfg.debug, "debug", false, "debug mode")
	flag.StringVar(&cfg.log_prefix, "log_prefix", "", "Log prefix")
	flag.BoolVar(&cfg.benchmark, "benchmark", false, "run benchmark after connect")

	flag.IntVar(&cfg.port, "port", 443, "quic port")
	flag.StringVar(&cfg.tls_ca, "ca", "", "TLS CA file. If not set system CAs will be used")

	flag.StringVar(&cfg.dev, "dev", "vpn%d", "network device")
	flag.IntVar(&cfg.mtu, "mtu", 1350, "MTU size")
	flag.StringVar(&cfg.netns, "netns", "", "Net Namespace for tun device")

	flag.StringVar(&cfg.config_file, "config_file", filename+".cfg", "Configuration file to read")

	flag.Parse()

	get_file_config(cfg.config_file)

	if cfg.debug {
		MAX_LOGLEVEL = LOG_DEBUG
	}
	setup_signals()

	log_info("Starting %s %s version %s build %s", BUILD_NAME, BUILD_TYPE, BUILD_VERSION, BUILD_DATE)
}

func get_server_config() {
	flag.StringVar(&cfg.listen, "listen", "0.0.0.0", "listening address")
	flag.StringVar(&cfg.ippool, "pool", "11.0.0.1/24", "IPv4 or IPv6 address pool")
	flag.IntVar(&cfg.max_pool_size, "max_pool_size", 32, "Maximum number of concurrent connections")
	flag.StringVar(&cfg.addroutes, "routes", "", "Additional routes to install")
	flag.StringVar(&cfg.users_file, "users_file", "users.db", "User database")
	flag.BoolVar(&cfg.client_auth, "client_auth", false, "Require mutual client authentication")
	flag.StringVar(&cfg.tls_cert, "cert", "fullchain.pem", "TLS certificate file")
	flag.StringVar(&cfg.tls_key, "key", "privkey.pem", "TLS private key file")
	get_config()

	if !cfg.client_auth {
		load_userdb(cfg.users_file)
	}
}

func get_client_config() {
	flag.StringVar(&cfg.hostname, "hostname", "", "remote server")
	flag.StringVar(&cfg.iprequest, "iprequest", "0.0.0.0", "IPv4 or IPv6 address to request")
	flag.StringVar(&cfg.username, "username", "", "username")
	flag.StringVar(&cfg.password, "password", "", "password")
	flag.StringVar(&cfg.tls_cert, "cert", "", "mTLS certificate file")
	flag.StringVar(&cfg.tls_key, "key", "", "mTLS private key file")
	get_config()
}
