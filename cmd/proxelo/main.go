// Command proxelo runs the Proxelo control plane.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"google.golang.org/protobuf/proto"

	"github.com/null-variable/proxelo/internal/compile"
	"github.com/null-variable/proxelo/internal/model"
)

var version = "dev"

const usage = `usage: proxelo <command>

commands:
  compile <config.json> <out.bin>   compile resources into a snapshot
  version                           print the version`

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	switch {
	case len(args) == 1 && args[0] == "version":
		fmt.Println("proxelo", version)
		return 0
	case len(args) == 3 && args[0] == "compile":
		if err := compileFile(args[1], args[2]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	default:
		fmt.Fprintln(os.Stderr, usage)
		return 2
	}
}

func compileFile(in, out string) error {
	raw, err := os.ReadFile(in)
	if err != nil {
		return err
	}
	var cfg model.Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("%s: %w", in, err)
	}
	snap, err := compile.Compile(cfg, 1)
	if err != nil {
		return err
	}
	b, err := proto.Marshal(snap)
	if err != nil {
		return err
	}
	return os.WriteFile(out, b, 0o644)
}
