package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"

	"eventhorizon/internal/packaging"
	"eventhorizon/internal/wire"
)

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
