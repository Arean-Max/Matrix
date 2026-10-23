package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"eventhorizon/internal/wire"
)

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
