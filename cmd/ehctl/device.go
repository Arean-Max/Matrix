package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"eventhorizon/internal/wire"
)

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
