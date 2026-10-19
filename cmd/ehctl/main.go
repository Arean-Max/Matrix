package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"eventhorizon/internal/version"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]

	var err error
	switch cmd {
	case "init":
		err = cmdInit(args)
	case "status":
		err = cmdStatus(args)
	case "license":
		err = cmdLicense(args)
	case "device":
		err = cmdDevice(args)
	case "packages":
		err = cmdPackages(args)
	case "audits":
		err = cmdAudits(args)
	case "tokens":
		err = cmdTokens(args)
	case "backup":
		err = cmdBackup(args)
	case "version":
		fmt.Println("ehctl", version.Version)
		return
	case "help", "-h", "--help":
		usage()
		return
	default:
		err = fmt.Errorf("unknown command %q (try: ehctl help)", cmd)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `ehctl — Event Horizon operator CLI

Usage:
  ehctl init   [--bootstrap-file FILE] [--out FILE] [--name NAME] [--role admin|read]
  ehctl status
  ehctl license create --customer NAME [--note TEXT] [--channel webhook:URL|manual] [--max-devices N]
  ehctl license list [--query TEXT] [--status active|suspended|revoked] [--limit N]
  ehctl license show ID
  ehctl license suspend|resume|revoke ID [--reason TEXT]
  ehctl license oob ID          # reveal the current pending activation code
  ehctl license unlock ID       # clear the failed-attempt ladder
  ehctl license clear-resets ID # wipe HWID reset counters after verification
  ehctl device list [--license ID]
  ehctl device revoke ID        # terminal for this binding
  ehctl device release ID       # allow a new binding
  ehctl packages import FILE.provision.json
  ehctl packages list
  ehctl packages revoke ID
  ehctl audits [--license ID] [--action ACTION] [--limit N] [--before ID]
  ehctl tokens create NAME --role admin|read
  ehctl tokens list
  ehctl tokens revoke ID
  ehctl backup --out FILE       # consistent database copy (SQLite VACUUM INTO)
  ehctl version

Common flags (any command): --server URL, --token TOKEN, --token-file FILE,
--ca PEM, --json. Defaults come from EHCTL_SERVER / EHCTL_TOKEN and
~/.ehctl/token.
`)
}

type globals struct {
	server    string
	token     string
	tokenFile string
	ca        string
	asJSON    bool
}

func commonFS(name string) (*flag.FlagSet, *globals) {
	g := &globals{}
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	fs.StringVar(&g.server, "server", os.Getenv("EHCTL_SERVER"), "server base URL, e.g. https://license.example.com:8443")
	fs.StringVar(&g.token, "token", "", "admin token (defaults to EHCTL_TOKEN or the token file)")
	fs.StringVar(&g.tokenFile, "token-file", defaultTokenFile(), "path to the saved admin token")
	fs.StringVar(&g.ca, "ca", "", "PEM file with the server CA or self-signed certificate")
	fs.BoolVar(&g.asJSON, "json", false, "print raw JSON responses")
	return fs, g
}

func defaultTokenFile() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".ehctl-token"
	}
	return filepath.Join(home, ".ehctl", "token")
}

func readFileTrim(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func parse(fs *flag.FlagSet, args []string) error {
	return fs.Parse(reorder(args))
}

func reorder(args []string) []string {
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if len(a) > 1 && a[0] == '-' && a != "--" {
			flags = append(flags, a)
			if strings.ContainsRune(a, '=') {
				continue
			}
			name := strings.TrimLeft(a, "-")

			if name == "json" || name == "h" || name == "help" {
				continue
			}
			if i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
		} else {
			positional = append(positional, a)
		}
	}
	return append(flags, positional...)
}
