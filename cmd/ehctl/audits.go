package main

import (
	"fmt"
	"net/url"

	"eventhorizon/internal/wire"
)

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
