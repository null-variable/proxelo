package main

import (
	"fmt"
	"strings"

	"github.com/null-variable/proxelo/test/conformance/coverage"
)

func report(results []CaseResult, list coverage.List, tested map[string]bool) string {
	var b strings.Builder
	passed, reqs := 0, 0
	for _, r := range results {
		reqs += r.Total
		if r.Passed() {
			passed++
		}
	}
	fmt.Fprintf(&b, "# Conformance against nginx %s\n\n", list.Nginx)
	fmt.Fprintf(&b, "%d of %d cases pass (%d requests).\n\n", passed, len(results), reqs)
	b.WriteString("| Case | Requests | Result | Directives |\n|---|---|---|---|\n")
	for _, r := range results {
		res := "pass"
		if !r.Passed() {
			res = fmt.Sprintf("**fail** (%d differ)", len(r.Diffs))
		}
		names := make([]string, len(r.Case.Directives))
		for i, d := range r.Case.Directives {
			_, names[i], _ = strings.Cut(d, "/")
		}
		fmt.Fprintf(&b, "| `%s` | %d | %s | %s |\n", r.Case.Name, r.Total, res, strings.Join(names, ", "))
	}
	for _, r := range results {
		for _, d := range r.Diffs {
			fmt.Fprintf(&b, "\n### %s: %s\n\n", r.Case.Name, d.Req)
			for _, l := range d.Lines {
				fmt.Fprintf(&b, "- %s\n", l)
			}
		}
	}
	b.WriteString("\n")
	b.WriteString(list.Markdown(tested))
	return b.String()
}
