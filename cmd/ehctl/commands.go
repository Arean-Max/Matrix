package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"eventhorizon/internal/packaging"
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
	if err := os.WriteFile(*out, []byte(created.Token+"\n"), 0o600); err != nil {
		return err
	}
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

func cmdLicense(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: ehctl license create|list|show|suspend|resume|revoke|oob|unlock|clear-resets ...")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "create":
		return cmdLicenseCreate(rest)
	case "list":
		return cmdLicenseList(rest)
	case "show":
		return cmdLicenseShow(rest)
	case "suspend":
		return cmdLicenseStatus(rest, "suspended")
	case "resume":
		return cmdLicenseStatus(rest, "active")
	case "revoke":
		return cmdLicenseStatus(rest, "revoked")
	case "oob":
		return cmdLicenseOOB(rest)
	case "unlock":
		return cmdLicenseUnlock(rest)
	case "clear-resets":
		return cmdLicenseClearResets(rest)
	default:
		return fmt.Errorf("unknown license subcommand %q", sub)
	}
}

func licenseKeyPath(id string) string {
	return "/admin/v1/licenses/" + url.PathEscape(id)
}

func cmdLicenseCreate(args []string) error {
	fs, g := commonFS("ehctl license create")
	customer := fs.String("customer", "", "customer name (required)")
	note := fs.String("note", "", "free-form note")
	channel := fs.String("channel", "", `delivery channel: "webhook:https://..." | "manual" | ""`)
	maxDevices := fs.Int("max-devices", 0, "trusted device limit (default 1)")
	if err := parse(fs, args); err != nil {
		return err
	}
	if strings.TrimSpace(*customer) == "" {
		return errors.New("--customer is required")
	}
	c, err := newClient(g, true)
	if err != nil {
		return err
	}
	var resp wire.LicenseCreateResponse
	if err := c.do(http.MethodPost, "/admin/v1/licenses", wire.LicenseCreateRequest{
		Customer: *customer, Note: *note, Channel: *channel, MaxDevices: *maxDevices,
	}, &resp); err != nil {
		return err
	}
	return printOrJSON(g, resp, func() {
		fmt.Printf("license id:  %s\n", resp.ID)
		fmt.Printf("license key: %s\n", resp.LicenseKey)
		fmt.Println("(the key is shown only once; store it safely)")
	})
}

func cmdLicenseList(args []string) error {
	fs, g := commonFS("ehctl license list")
	query := fs.String("query", "", "substring of customer, note or id")
	status := fs.String("status", "", "active|suspended|revoked")
	limit := fs.Int("limit", 50, "page size")
	offset := fs.Int("offset", 0, "page offset")
	if err := parse(fs, args); err != nil {
		return err
	}
	c, err := newClient(g, true)
	if err != nil {
		return err
	}
	path := fmt.Sprintf("/admin/v1/licenses?limit=%d&offset=%d", *limit, *offset)
	if *query != "" {
		path += "&query=" + url.QueryEscape(*query)
	}
	if *status != "" {
		path += "&status=" + url.QueryEscape(*status)
	}
	var resp wire.LicenseListResponse
	if err := fetch(c, path, &resp); err != nil {
		return err
	}
	return printOrJSON(g, resp, func() {
		for _, l := range resp.Licenses {
			fmt.Printf("%s  %-9s  %-24s  devices=%d sessions=%d  created=%s\n",
				l.ID, l.Status, trunc(l.Customer, 24), l.Devices, l.ActiveSessions, ts(l.CreatedAt))
		}
		fmt.Printf("total: %d\n", resp.Total)
	})
}

func cmdLicenseShow(args []string) error {
	fs, g := commonFS("ehctl license show")
	if err := parse(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: ehctl license show ID")
	}
	c, err := newClient(g, true)
	if err != nil {
		return err
	}
	var v wire.LicenseView
	if err := fetch(c, licenseKeyPath(fs.Arg(0)), &v); err != nil {
		return err
	}
	return printOrJSON(g, v, func() {
		fmt.Printf("id:        %s\n", v.ID)
		fmt.Printf("customer:  %s\n", v.Customer)
		fmt.Printf("status:    %s\n", v.Status)
		fmt.Printf("note:      %s\n", v.Note)
		fmt.Printf("channel:   %s\n", v.Channel)
		fmt.Printf("devices:   %d trusted, %d active sessions\n", v.Devices, v.ActiveSessions)
		if v.LastResetAt != 0 {
			fmt.Printf("resets:    %d (last %s)\n", v.ResetCount, ts(v.LastResetAt))
		} else {
			fmt.Printf("resets:    %d\n", v.ResetCount)
		}
		fmt.Printf("created:   %s\n", ts(v.CreatedAt))
		fmt.Printf("updated:   %s\n", ts(v.UpdatedAt))
	})
}

func cmdLicenseStatus(args []string, status string) error {
	fs, g := commonFS("ehctl license " + status)
	reason := fs.String("reason", "", "reason recorded in the audit trail")
	if err := parse(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: ehctl license %s ID [--reason TEXT]", status)
	}
	c, err := newClient(g, true)
	if err != nil {
		return err
	}
	path := licenseKeyPath(fs.Arg(0)) + "/" + statusPath(status)
	if err := c.do(http.MethodPost, path, wire.ReasonRequest{Reason: *reason}, nil); err != nil {
		return err
	}
	fmt.Printf("license %s: %s\n", fs.Arg(0), status)
	return nil
}

func statusPath(status string) string {
	switch status {
	case "active":
		return "resume"
	case "suspended":
		return "suspend"
	default:
		return "revoke"
	}
}

func cmdLicenseOOB(args []string) error {
	fs, g := commonFS("ehctl license oob")
	if err := parse(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: ehctl license oob ID")
	}
	c, err := newClient(g, true)
	if err != nil {
		return err
	}
	var v wire.OOBView
	if err := fetch(c, licenseKeyPath(fs.Arg(0))+"/oob", &v); err != nil {
		return err
	}
	return printOrJSON(g, v, func() {
		fmt.Printf("code:        %s\n", v.Code)
		fmt.Printf("fingerprint: %s\n", v.Fingerprint)
		fmt.Printf("expires:     %s\n", ts(v.ExpiresAt))
		fmt.Printf("attempts:    %d\n", v.Attempts)
		if v.LockedUntil != 0 {
			fmt.Printf("locked until %s\n", ts(v.LockedUntil))
		}
	})
}

func cmdLicenseUnlock(args []string) error {
	fs, g := commonFS("ehctl license unlock")
	if err := parse(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: ehctl license unlock ID")
	}
	c, err := newClient(g, true)
	if err != nil {
		return err
	}
	if err := c.do(http.MethodPost, licenseKeyPath(fs.Arg(0))+"/oob/unlock", nil, nil); err != nil {
		return err
	}
	fmt.Printf("license %s: OOB attempt ladder cleared\n", fs.Arg(0))
	return nil
}

func cmdLicenseClearResets(args []string) error {
	fs, g := commonFS("ehctl license clear-resets")
	if err := parse(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: ehctl license clear-resets ID")
	}
	c, err := newClient(g, true)
	if err != nil {
		return err
	}
	var v wire.LicenseView
	if err := c.do(http.MethodPost, licenseKeyPath(fs.Arg(0))+"/resets/clear", nil, &v); err != nil {
		return err
	}
	return printOrJSON(g, v, func() {
		fmt.Printf("license %s: reset counters cleared\n", v.ID)
	})
}

func cmdDevice(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: ehctl device list|revoke|release ...")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "list":
		return cmdDeviceList(rest)
	case "revoke":
		return cmdDeviceRevoke(rest)
	case "release":
		return cmdDeviceRelease(rest)
	default:
		return fmt.Errorf("unknown device subcommand %q", sub)
	}
}

func cmdDeviceList(args []string) error {
	fs, g := commonFS("ehctl device list")
	licenseID := fs.String("license", "", "only devices of this license")
	if err := parse(fs, args); err != nil {
		return err
	}
	c, err := newClient(g, true)
	if err != nil {
		return err
	}
	path := "/admin/v1/devices"
	if *licenseID != "" {
		path += "?license_id=" + url.QueryEscape(*licenseID)
	}
	var resp wire.DeviceListResponse
	if err := fetch(c, path, &resp); err != nil {
		return err
	}
	return printOrJSON(g, resp, func() {
		for _, d := range resp.Devices {
			fmt.Printf("%s  %-9s  %-10s  %-12s  bound=%s  seen=%s\n",
				d.ID, d.Status, d.Trust, trunc(d.Fingerprint, 12), ts(d.BoundAt), ts(d.LastSeenAt))
		}
		if len(resp.Devices) == 0 {
			fmt.Println("no devices")
		}
	})
}

func cmdDeviceRevoke(args []string) error {
	fs, g := commonFS("ehctl device revoke")
	if err := parse(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: ehctl device revoke ID")
	}
	c, err := newClient(g, true)
	if err != nil {
		return err
	}
	if err := c.do(http.MethodPost, "/admin/v1/devices/"+url.PathEscape(fs.Arg(0))+"/revoke", nil, nil); err != nil {
		return err
	}
	fmt.Printf("device %s revoked (terminal; use device release to allow a new binding)\n", fs.Arg(0))
	return nil
}

func cmdDeviceRelease(args []string) error {
	fs, g := commonFS("ehctl device release")
	if err := parse(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: ehctl device release ID")
	}
	c, err := newClient(g, true)
	if err != nil {
		return err
	}
	if err := c.do(http.MethodPost, "/admin/v1/devices/"+url.PathEscape(fs.Arg(0))+"/release", nil, nil); err != nil {
		return err
	}
	fmt.Printf("device %s released (its sessions are gone; a new binding needs an activation code)\n", fs.Arg(0))
	return nil
}

func cmdPackages(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: ehctl packages import|list|revoke ...")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "import":
		return cmdPackagesImport(rest)
	case "list":
		return cmdPackagesList(rest)
	case "revoke":
		return cmdPackagesRevoke(rest)
	default:
		return fmt.Errorf("unknown packages subcommand %q", sub)
	}
}

func cmdPackagesImport(args []string) error {
	fs, g := commonFS("ehctl packages import")
	if err := parse(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: ehctl packages import FILE.provision.json")
	}
	raw, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	prov, err := packaging.ParseProvision(raw)
	if err != nil {
		return err
	}
	c, err := newClient(g, true)
	if err != nil {
		return err
	}
	if err := c.do(http.MethodPost, "/admin/v1/packages", wire.PackageImportRequest{
		Version: prov.Version, ID: prov.ID, Name: prov.Name,
		SHA256: prov.SHA256, Key: prov.Key,
	}, nil); err != nil {
		return err
	}
	fmt.Printf("package %s imported (sha256 %s)\n", prov.ID, prov.SHA256)
	return nil
}

func cmdPackagesList(args []string) error {
	fs, g := commonFS("ehctl packages list")
	if err := parse(fs, args); err != nil {
		return err
	}
	c, err := newClient(g, true)
	if err != nil {
		return err
	}
	var resp wire.PackageListResponse
	if err := fetch(c, "/admin/v1/packages", &resp); err != nil {
		return err
	}
	return printOrJSON(g, resp, func() {
		for _, p := range resp.Packages {
			fmt.Printf("%s  %-8s  %-24s  %s  created=%s\n", p.ID, p.Status, trunc(p.Name, 24), p.SHA256[:12]+"…", ts(p.CreatedAt))
		}
		if len(resp.Packages) == 0 {
			fmt.Println("no packages")
		}
	})
}

func cmdPackagesRevoke(args []string) error {
	fs, g := commonFS("ehctl packages revoke")
	if err := parse(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: ehctl packages revoke ID")
	}
	c, err := newClient(g, true)
	if err != nil {
		return err
	}
	if err := c.do(http.MethodPost, "/admin/v1/packages/"+url.PathEscape(fs.Arg(0))+"/revoke", nil, nil); err != nil {
		return err
	}
	fmt.Printf("package %s revoked (clients can no longer fetch its key)\n", fs.Arg(0))
	return nil
}

func cmdAudits(args []string) error {
	fs, g := commonFS("ehctl audits")
	licenseID := fs.String("license", "", "only events of this license")
	action := fs.String("action", "", "exact action, e.g. oob.fail")
	limit := fs.Int("limit", 100, "page size")
	before := fs.Int64("before", 0, "only events with id < N (paging)")
	if err := parse(fs, args); err != nil {
		return err
	}
	c, err := newClient(g, true)
	if err != nil {
		return err
	}
	path := fmt.Sprintf("/admin/v1/audits?limit=%d", *limit)
	if *licenseID != "" {
		path += "&license_id=" + url.QueryEscape(*licenseID)
	}
	if *action != "" {
		path += "&action=" + url.QueryEscape(*action)
	}
	if *before > 0 {
		path += fmt.Sprintf("&before_id=%d", *before)
	}
	var resp wire.AuditListResponse
	if err := fetch(c, path, &resp); err != nil {
		return err
	}
	return printOrJSON(g, resp, func() {
		for _, a := range resp.Audits {
			line := fmt.Sprintf("%s  %-12s  %-22s", ts(a.TS), a.Actor, a.Action)
			if a.Detail != "" {
				line += "  " + a.Detail
			}
			fmt.Println(line)
		}
		if len(resp.Audits) == 0 {
			fmt.Println("no audit events")
		}
	})
}

func cmdTokens(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: ehctl tokens create|list|revoke ...")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "create":
		return cmdTokensCreate(rest)
	case "list":
		return cmdTokensList(rest)
	case "revoke":
		return cmdTokensRevoke(rest)
	default:
		return fmt.Errorf("unknown tokens subcommand %q", sub)
	}
}

func cmdTokensCreate(args []string) error {
	fs, g := commonFS("ehctl tokens create")
	role := fs.String("role", "", "role: admin|read")
	if err := parse(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: ehctl tokens create NAME --role admin|read")
	}
	c, err := newClient(g, true)
	if err != nil {
		return err
	}
	var resp wire.TokenCreateResponse
	if err := c.do(http.MethodPost, "/admin/v1/tokens",
		wire.TokenCreateRequest{Name: fs.Arg(0), Role: *role}, &resp); err != nil {
		return err
	}
	return printOrJSON(g, resp, func() {
		fmt.Printf("token id: %s\n", resp.ID)
		fmt.Printf("token:    %s\n(shown once)\n", resp.Token)
	})
}

func cmdTokensList(args []string) error {
	fs, g := commonFS("ehctl tokens list")
	if err := parse(fs, args); err != nil {
		return err
	}
	c, err := newClient(g, true)
	if err != nil {
		return err
	}
	var resp wire.TokenListResponse
	if err := fetch(c, "/admin/v1/tokens", &resp); err != nil {
		return err
	}
	return printOrJSON(g, resp, func() {
		for _, t := range resp.Tokens {
			state := "active"
			if t.RevokedAt != 0 {
				state = "revoked"
			}
			fmt.Printf("%s  %-16s  %-5s  %-7s  created=%s  used=%s\n",
				t.ID, trunc(t.Name, 16), t.Role, state, ts(t.CreatedAt), ts(t.LastUsedAt))
		}
	})
}

func cmdTokensRevoke(args []string) error {
	fs, g := commonFS("ehctl tokens revoke")
	if err := parse(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: ehctl tokens revoke ID")
	}
	c, err := newClient(g, true)
	if err != nil {
		return err
	}
	if err := c.do(http.MethodPost, "/admin/v1/tokens/"+url.PathEscape(fs.Arg(0))+"/revoke", nil, nil); err != nil {
		return err
	}
	fmt.Printf("token %s revoked\n", fs.Arg(0))
	return nil
}

func cmdBackup(args []string) error {
	fs, g := commonFS("ehctl backup")
	out := fs.String("out", "", "destination file (must not exist)")
	if err := parse(fs, args); err != nil {
		return err
	}
	if strings.TrimSpace(*out) == "" {
		return errors.New("usage: ehctl backup --out FILE")
	}
	c, err := newClient(g, true)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create backup file: %w", err)
	}
	if err := c.download("/admin/v1/backup", f); err != nil {
		f.Close()
		_ = os.Remove(*out)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(*out)
		return err
	}
	st, err := os.Stat(*out)
	if err != nil {
		return err
	}
	fmt.Printf("backup written: %s (%d bytes)\n", *out, st.Size())
	fmt.Println("note: the master key and TLS files are not part of it (see OPERATIONS.md)")
	return nil
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
