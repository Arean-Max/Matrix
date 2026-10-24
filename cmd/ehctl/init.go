package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"eventhorizon/internal/wire"
)

func cmdInit(args []string) error {
	fs, g := commonFS("ehctl init")
	bootstrapFile := fs.String("bootstrap-file", "", "file with the bootstrap token printed by eh-server")
	name := fs.String("name", "ehctl", "name for the first admin token")
	role := fs.String("role", "admin", "role for the first admin token: admin|read")
	out := fs.String("out", defaultTokenFile(), "where to save the new admin token")
	if err := parse(fs, args); err != nil {
		return err
	}

	bootstrap := strings.TrimSpace(g.token)
	if *bootstrapFile != "" {
		raw, err := readFileTrim(*bootstrapFile)
		if err != nil {
			return fmt.Errorf("read bootstrap file: %w", err)
		}
		bootstrap = raw
	}
	if bootstrap == "" {
		return errors.New("provide --bootstrap-file (printed by eh-server on first start) or --token")
	}
	g.token = bootstrap

	c, err := newClient(g, false)
	if err != nil {
		return err
	}
	var created wire.TokenCreateResponse
	if err := c.do(http.MethodPost, "/admin/v1/tokens", wire.TokenCreateRequest{Name: *name, Role: *role}, &created); err != nil {
		return err
	}

	c.token = created.Token
	var st wire.StatusResponse
	if err := fetch(c, "/admin/v1/status", &st); err != nil {
		return fmt.Errorf("token created but verification failed: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(*out), 0o700); err != nil {
		return err
	}
	tmpToken := *out + ".tmp"
	if err := os.WriteFile(tmpToken, []byte(created.Token+"\n"), 0o600); err != nil {
		return err
	}
	_ = os.Chmod(tmpToken, 0o600)
	if err := os.Rename(tmpToken, *out); err != nil {
		_ = os.Remove(*out)
		if err := os.Rename(tmpToken, *out); err != nil {
			return err
		}
	}
	_ = os.Chmod(*out, 0o600)
	fmt.Printf("connected to eh-server %s (uptime %ds, licenses %d, devices %d)\n",
		st.Version, st.UptimeS, st.Licenses, st.Devices)
	fmt.Printf("admin token %q saved to %s\n", *name, *out)
	fmt.Printf("token: %s\n(copy it now if you want a second copy)\n", created.Token)
	return nil
}

func cmdStatus(args []string) error {
	fs, g := commonFS("ehctl status")
	if err := parse(fs, args); err != nil {
		return err
	}
	c, err := newClient(g, true)
	if err != nil {
		return err
	}
	var st wire.StatusResponse
	if err := fetch(c, "/admin/v1/status", &st); err != nil {
		return err
	}
	return printOrJSON(g, st, func() {
		fmt.Printf("eh-server     %s\n", st.Version)
		fmt.Printf("uptime        %ds\n", st.UptimeS)
		fmt.Printf("server time   %s\n", ts(st.ServerTime))
		fmt.Printf("licenses      %d\n", st.Licenses)
		fmt.Printf("devices       %d\n", st.Devices)
		fmt.Printf("sessions      %d\n", st.ActiveSessions)
	})
}
