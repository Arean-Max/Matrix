package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"

	"event-horizon/builder/internal/packer"
	"event-horizon/builder/internal/synthesizer"
	"event-horizon/shared/whitebox"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "pack":
		handlePack(os.Args[2:])
	case "deploy-bundle":
		handleDeployBundle(os.Args[2:])
	case "generate-whitebox":
		handleGenerateWhiteBox(os.Args[2:])
	default:
		fmt.Printf("Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Event Horizon Spec v12 Builder CLI")
	fmt.Println("Usage:")
	fmt.Println("  builder pack --mode=[PATH_A|PATH_A_PLUS|PATH_B] --input=<path> --out=<path>")
	fmt.Println("  builder deploy-bundle --out=<dir> --domain=<domain> [--port=8443]")
	fmt.Println("  builder generate-whitebox --key=<32-byte-hex> --out=<file.h>")
}

func handlePack(args []string) {
	fs := flag.NewFlagSet("pack", flag.ExitOnError)
	modeStr := fs.String("mode", "PATH_A", "Packaging mode (PATH_A, PATH_A_PLUS, PATH_B)")
	input := fs.String("input", "", "Path to input vendor binary (.dll or .exe)")
	out := fs.String("out", "protected_output.bin", "Path to output protected package")
	serverURL := fs.String("server", "https://licensing.vendor.local:8443", "Server base URL")
	_ = fs.Parse(args)

	if *input == "" {
		log.Fatal("[-] Flag --input is required")
	}

	res, err := packer.PackTarget(packer.PackOptions{
		Mode:       packer.PackagingMode(*modeStr),
		InputFile:  *input,
		OutputFile: *out,
		ServerURL:  *serverURL,
	})
	if err != nil {
		log.Fatalf("[-] Packaging failed: %v", err)
	}

	fmt.Printf("[+] Package successfully created: %s (%d bytes)\n", res.OutputFile, res.OutputSize)
	fmt.Printf("[+] EDR Compliance: %s\n", res.EDRCompliance)
	if res.WarningMessage != "" {
		fmt.Printf("[!] WARNING: %s\n", res.WarningMessage)
	}
}

func handleDeployBundle(args []string) {
	fs := flag.NewFlagSet("deploy-bundle", flag.ExitOnError)
	outDir := fs.String("out", "eh-deploy-bundle", "Output bundle directory")
	domain := fs.String("domain", "licensing.company.com", "Server FQDN")
	port := fs.Int("port", 8443, "Server port")
	_ = fs.Parse(args)

	res, err := synthesizer.GenerateDeployBundle(synthesizer.BundleOptions{
		OutputDir: *outDir,
		Domain:    *domain,
		Port:      *port,
	})
	if err != nil {
		log.Fatalf("[-] Bundle generation failed: %v", err)
	}

	fmt.Printf("[+] Deployment bundle generated in: %s\n", res.BundleDir)
	fmt.Printf("[+] Docker Compose: %s\n", res.DockerCompose)
	fmt.Printf("[+] Signed Release Manifest: %s\n", res.ReleaseSignature[:32]+"...")
}

func handleGenerateWhiteBox(args []string) {
	fs := flag.NewFlagSet("generate-whitebox", flag.ExitOnError)
	keyHex := fs.String("key", "", "32-byte master encryption key in hex")
	out := fs.String("out", "whitebox_network.h", "Path to generated C header")
	_ = fs.Parse(args)

	keyBytes, err := hex.DecodeString(*keyHex)
	if err != nil || len(keyBytes) != 32 {
		log.Fatal("[-] Flag --key must be 64 hexadecimal characters (32 bytes)")
	}

	wb, err := whitebox.GenerateWhiteBoxNetwork(keyBytes)
	if err != nil {
		log.Fatalf("[-] Failed to generate white-box network: %v", err)
	}

	header := wb.ExportCHeader("g_whitebox_network")
	if err := os.WriteFile(*out, []byte(header), 0644); err != nil {
		log.Fatalf("[-] Failed to write header: %v", err)
	}

	fmt.Printf("[+] White-Box network header exported to: %s\n", *out)
}
