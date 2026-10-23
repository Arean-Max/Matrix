package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

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
