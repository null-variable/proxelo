package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/null-variable/proxelo/internal/breakglass"
)

// adminCmd runs a break-glass command against a running control plane over
// its local socket.
func adminCmd(args []string) error {
	fs := flag.NewFlagSet("admin", flag.ContinueOnError)
	dataDir := fs.String("data", envOr("PROXELO_DATA", "/var/lib/proxelo"), "data directory (env PROXELO_DATA)")
	socket := fs.String("socket", envOr("PROXELO_BREAK_GLASS_SOCKET", ""), "break-glass socket (env PROXELO_BREAK_GLASS_SOCKET; default <data>/run/admin.sock)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *socket == "" {
		*socket = filepath.Join(*dataDir, "run", "admin.sock")
	}
	rest := fs.Args()
	if len(rest) == 0 {
		return fmt.Errorf("admin: want reset-password, rollback or bind")
	}
	sub := flag.NewFlagSet("admin "+rest[0], flag.ContinueOnError)
	var cmd string
	var req any
	switch rest[0] {
	case "reset-password":
		user := sub.String("user", "", "account name")
		if err := sub.Parse(rest[1:]); err != nil {
			return err
		}
		if *user == "" || sub.NArg() > 0 {
			return fmt.Errorf("usage: proxelo admin reset-password --user <name>")
		}
		cmd, req = "reset-password", map[string]string{"user": *user}
	case "rollback":
		to := sub.String("to", "last-confirmed", `revision number or "last-confirmed"`)
		if err := sub.Parse(rest[1:]); err != nil {
			return err
		}
		if sub.NArg() > 0 {
			return fmt.Errorf("usage: proxelo admin rollback --to <revision|last-confirmed>")
		}
		cmd, req = "rollback", map[string]string{"to": *to}
	case "bind":
		if err := sub.Parse(rest[1:]); err != nil {
			return err
		}
		if sub.NArg() != 1 {
			return fmt.Errorf("usage: proxelo admin bind <addr>")
		}
		cmd, req = "bind", map[string]string{"addr": sub.Arg(0)}
	default:
		return fmt.Errorf("admin: unknown command %q", rest[0])
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var resp map[string]any
	if err := breakglass.Call(ctx, *socket, cmd, req, &resp); err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(resp)
}
