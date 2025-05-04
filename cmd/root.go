package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/denniskniep/DeviceCodePhishing/pkg/utils"

	"github.com/spf13/cobra"
)

var (
	noBanner bool
	verbose  bool
	version  = "1.0.1"
)

var rootCmd = &cobra.Command{
	Use:   "DeviceCodePhishing",
	Short: "Advanced phishing tool using Device Code Flow",
	Long: `DeviceCodePhishing is an advanced phishing tool that leverages the Device Code Flow to obtain access tokens.

This tool allows phishing Azure tokens by automating the device authentication flow, bypassing traditional
security measures and working even when FIDO authentication is in place.

Available Commands:
  server    Start the phishing server

Global Flags:
  --no-banner        Do not display the banner
  -v, --verbose      Enable verbose logging
  --version          Display version information
  -h, --help         Display this help message

For help with a specific command, use:
  DeviceCodePhishing [command] --help

Examples:
  DeviceCodePhishing server --help
  DeviceCodePhishing --version
`,
	Version: version,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
		slog.SetDefault(logger)
		slog.SetLogLoggerLevel(slog.LevelInfo)

		if verbose {
			slog.SetLogLoggerLevel(slog.LevelDebug)
		}

		// Only print banner if not showing help, version, or similar
		commandPath := cmd.CommandPath()
		if !noBanner &&
			cmd.Short != "Help about any command" &&
			!strings.HasPrefix(cmd.Short, "Generate the autocompletion script for") &&
			!strings.Contains(commandPath, "help") {
			utils.PrintBanner(version)
		}
	},
}

func Execute() {
	// Disable default help command to clean up help output
	rootCmd.SetHelpCommand(&cobra.Command{Hidden: true})

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&noBanner, "no-banner", false, "Do not display the banner")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose logging")

	// Customize usage template to better organize the help output
	rootCmd.SetUsageTemplate(`Usage:{{if .Runnable}}
  {{.UseLine}}{{end}}{{if .HasAvailableSubCommands}}
  {{.CommandPath}} [command]{{end}}{{if gt (len .Aliases) 0}}

Aliases:
  {{.NameAndAliases}}{{end}}{{if .HasExample}}

Examples:
{{.Example}}{{end}}{{if .HasAvailableSubCommands}}

Available Commands:{{range .Commands}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

Flags:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailablePersistentFlags}}

Global Flags:
{{.PersistentFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasHelpSubCommands}}

Additional help topics:{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
  {{rpad .CommandPath .CommandPathPadding}} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}

Use "{{.CommandPath}} [command] --help" for more information about a command.{{end}}
`)
}
