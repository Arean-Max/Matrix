package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"eventhorizon/internal/packaging"
	"eventhorizon/internal/version"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "pack":
		err = cmdPack(os.Args[2:])
	case "verify":
		err = cmdVerify(os.Args[2:])
	case "version":
		fmt.Println("eh-builder", version.Version)
		return
	case "help", "-h", "--help":
		usage()
		return
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `eh-builder — Event Horizon payload packer

Usage:
  eh-builder pack --id ID --name NAME --in PAYLOAD [--out DIR]
      Writes ID.ehpkg (safe to ship) and ID.provision.json (SECRET: import
      with "ehctl packages import", then delete or store offline).

  eh-builder verify --in ID.ehpkg [--provision ID.provision.json]
      Prints the container header; with the provision file it decrypts the
      payload and checks the sha256.

  eh-builder version
`)
}

func cmdPack(args []string) error {
	fs := flag.NewFlagSet("eh-builder pack", flag.ExitOnError)
	id := fs.String("id", "", "package id: 1..64 lowercase letters, digits, dot, dash, underscore")
	name := fs.String("name", "", "human-readable payload name")
	in := fs.String("in", "", "file to pack")
	out := fs.String("out", ".", "output directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == "" || *name == "" || *in == "" {
		return errors.New("--id, --name and --in are required")
	}
	payload, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	container, prov, err := packaging.Seal(payload, *id, *name, "eh-builder "+version.Version, now)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		return err
	}
	containerPath := filepath.Join(*out, *id+".ehpkg")
	provisionPath := filepath.Join(*out, *id+".provision.json")
	if err := os.WriteFile(containerPath, container, 0o644); err != nil {
		return err
	}
	provJSON, err := json.MarshalIndent(prov, "", "  ")
	if err != nil {
		return err
	}
	provJSON = append(provJSON, '\n')
	if err := os.WriteFile(provisionPath, provJSON, 0o600); err != nil {
		return err
	}

	fmt.Printf("container: %s (%d bytes)\n", containerPath, len(container))
	fmt.Printf("provision: %s (SECRET — import then delete)\n", provisionPath)
	fmt.Printf("payload:   %d bytes, sha256 %s\n", len(payload), prov.SHA256)
	fmt.Println("next: ehctl packages import " + provisionPath)
	return nil
}

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("eh-builder verify", flag.ExitOnError)
	in := fs.String("in", "", "container file")
	provision := fs.String("provision", "", "optional provision file to decrypt and check the payload")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" {
		return errors.New("--in is required")
	}
	container, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	hdr, _, err := packaging.Inspect(container)
	if err != nil {
		return err
	}
	fmt.Printf("id:      %s\nname:    %s\nbuilder: %s\ncreated: %s\nsha256:  %s\n",
		hdr.ID, hdr.Name, hdr.Builder, time.Unix(hdr.CreatedAt, 0).Format("2006-01-02 15:04:05"), hdr.SHA256)

	if *provision == "" {
		fmt.Println("(no --provision given; header only)")
		return nil
	}
	raw, err := os.ReadFile(*provision)
	if err != nil {
		return err
	}
	prov, err := packaging.ParseProvision(raw)
	if err != nil {
		return err
	}
	if prov.ID != hdr.ID || prov.SHA256 != hdr.SHA256 {
		return errors.New("provision does not match the container")
	}
	key, err := prov.KeyBytes()
	if err != nil {
		return err
	}
	payload, _, err := packaging.Open(container, key)
	if err != nil {
		return err
	}
	fmt.Printf("decrypted OK: %d bytes\n", len(payload))
	return nil
}
