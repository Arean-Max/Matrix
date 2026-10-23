package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"eventhorizon/internal/wire"
)

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
