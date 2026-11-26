// Package nginx converts nginx configuration into Proxelo resources.
//
// Parse reads nginx.conf syntax into a directive tree that follows
// include, like crossplane's AST. Convert turns the tree into a model.Config
// and a report that classifies every directive it met.
package nginx

import (
	"fmt"
	"path"
	"sort"
	"strings"
)

// Directive is one nginx directive with its arguments and, for a block, its
// children.
type Directive struct {
	Name  string       `json:"directive"`
	Args  []string     `json:"args,omitempty"`
	File  string       `json:"file"`
	Line  int          `json:"line"`
	Block []*Directive `json:"block,omitempty"`
	// The directive opened a block, even an empty one.
	IsBlock bool `json:"-"`
}

// Files maps paths, as include names them, to file contents.
type Files map[string]string

// ParseError is a syntax error at a position.
type ParseError struct {
	File string
	Line int
	Msg  string
}

func (e *ParseError) Error() string { return fmt.Sprintf("%s:%d: %s", e.File, e.Line, e.Msg) }

type token struct {
	text   string
	line   int
	quoted bool
}

// lex splits nginx syntax into words, "{", "}" and ";", with quotes and
// escapes resolved and comments dropped.
func lex(file, src string) ([]token, error) {
	var out []token
	line := 1
	i := 0
	for i < len(src) {
		c := src[i]
		switch {
		case c == '\n':
			line++
			i++
		case c == ' ' || c == '\t' || c == '\r':
			i++
		case c == '#':
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case c == '{' || c == '}' || c == ';':
			out = append(out, token{text: string(c), line: line})
			i++
		case c == '"' || c == '\'':
			start := line
			var b strings.Builder
			i++
			for {
				if i >= len(src) {
					return nil, &ParseError{file, start, "unterminated quote"}
				}
				ch := src[i]
				if ch == c {
					i++
					break
				}
				if ch == '\\' && i+1 < len(src) {
					unescape(&b, src[i+1])
					i += 2
					continue
				}
				if ch == '\n' {
					line++
				}
				b.WriteByte(ch)
				i++
			}
			out = append(out, token{text: b.String(), line: start, quoted: true})
		default:
			start := line
			var b strings.Builder
			// A "{" inside a variable such as ${name} belongs to the word.
			brace := 0
			for i < len(src) {
				ch := src[i]
				if ch == '\\' && i+1 < len(src) {
					unescape(&b, src[i+1])
					i += 2
					continue
				}
				if ch == '$' && i+1 < len(src) && src[i+1] == '{' {
					b.WriteString("${")
					brace++
					i += 2
					continue
				}
				if ch == '}' && brace > 0 {
					brace--
					b.WriteByte(ch)
					i++
					continue
				}
				if ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' || ch == ';' || ch == '{' || ch == '}' || ch == '"' || ch == '\'' {
					break
				}
				b.WriteByte(ch)
				i++
			}
			out = append(out, token{text: b.String(), line: start})
		}
	}
	return out, nil
}

// unescape writes the escape \next the way ngx_conf_read_token does:
// \" \' \\ \t \r \n are decoded, any other backslash stays (regexes keep
// \.).
func unescape(b *strings.Builder, next byte) {
	switch next {
	case '"', '\'', '\\':
		b.WriteByte(next)
	case 't':
		b.WriteByte('\t')
	case 'r':
		b.WriteByte('\r')
	case 'n':
		b.WriteByte('\n')
	default:
		b.WriteByte('\\')
		b.WriteByte(next)
	}
}

type parser struct {
	files Files
	// Files being included, against cycles.
	stack []string
}

// Parse reads the file main from files and follows include directives,
// whose glob patterns are matched against the other names in files.
// Relative include paths are taken from the directory of main, as nginx
// does with its prefix.
func Parse(files Files, main string) ([]*Directive, error) {
	p := &parser{files: files}
	return p.file(main, path.Dir(main))
}

func (p *parser) file(name, base string) ([]*Directive, error) {
	src, ok := p.files[name]
	if !ok {
		return nil, fmt.Errorf("%s: not found", name)
	}
	for _, f := range p.stack {
		if f == name {
			return nil, fmt.Errorf("%s: include cycle", name)
		}
	}
	p.stack = append(p.stack, name)
	defer func() { p.stack = p.stack[:len(p.stack)-1] }()
	toks, err := lex(name, src)
	if err != nil {
		return nil, err
	}
	ds, rest, err := p.block(name, base, toks, false)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, &ParseError{name, rest[0].line, `unexpected "}"`}
	}
	return ds, nil
}

// block parses directives until "}" (inner) or the end.
func (p *parser) block(file, base string, toks []token, inner bool) ([]*Directive, []token, error) {
	var out []*Directive
	for len(toks) > 0 {
		t := toks[0]
		if !t.quoted && t.text == "}" {
			if !inner {
				return nil, nil, &ParseError{file, t.line, `unexpected "}"`}
			}
			return out, toks[1:], nil
		}
		if !t.quoted && (t.text == ";" || t.text == "{") {
			return nil, nil, &ParseError{file, t.line, fmt.Sprintf("unexpected %q", t.text)}
		}
		d := &Directive{Name: t.text, File: file, Line: t.line}
		toks = toks[1:]
		for {
			if len(toks) == 0 {
				return nil, nil, &ParseError{file, t.line, fmt.Sprintf("%s: unexpected end of file", d.Name)}
			}
			a := toks[0]
			toks = toks[1:]
			if !a.quoted && a.text == ";" {
				break
			}
			if !a.quoted && a.text == "{" {
				d.IsBlock = true
				var err error
				d.Block, toks, err = p.block(file, base, toks, true)
				if err != nil {
					return nil, nil, err
				}
				break
			}
			if !a.quoted && a.text == "}" {
				return nil, nil, &ParseError{file, a.line, `unexpected "}"`}
			}
			d.Args = append(d.Args, a.text)
		}
		if d.Name == "include" && !d.IsBlock && len(d.Args) == 1 {
			inc, err := p.include(d, base)
			if err != nil {
				return nil, nil, err
			}
			out = append(out, inc...)
			continue
		}
		out = append(out, d)
	}
	if inner {
		return nil, nil, &ParseError{file, lastLine(toks), "unexpected end of file, expecting \"}\""}
	}
	return out, nil, nil
}

func lastLine(toks []token) int {
	if len(toks) == 0 {
		return 0
	}
	return toks[len(toks)-1].line
}

// include expands an include directive. A pattern that matches nothing is
// an error unless it has a wildcard, as in nginx.
func (p *parser) include(d *Directive, base string) ([]*Directive, error) {
	pat := d.Args[0]
	if !path.IsAbs(pat) {
		pat = path.Join(base, pat)
	}
	var names []string
	for n := range p.files {
		if ok, _ := path.Match(pat, n); ok {
			names = append(names, n)
		}
	}
	if len(names) == 0 && path.IsAbs(d.Args[0]) {
		names = p.rebased(pat, base)
	}
	sort.Strings(names)
	if len(names) == 0 && !strings.ContainsAny(pat, "*?[") {
		// Kept for the report: nginx would refuse the configuration.
		return []*Directive{d}, nil
	}
	var out []*Directive
	for _, n := range names {
		ds, err := p.file(n, base)
		if err != nil {
			return nil, err
		}
		out = append(out, ds...)
	}
	return out, nil
}

// rebased matches an absolute include that names nothing in the upload
// against the main file's directory: an archive of /etc/nginx holding
// conf.d/ at its top still resolves /etc/nginx/conf.d/*.conf. Leading
// elements are dropped one at a time; the file name and its directory
// always stay.
func (p *parser) rebased(pat, base string) []string {
	parts := strings.Split(strings.TrimPrefix(pat, "/"), "/")
	for i := 1; i <= len(parts)-2; i++ {
		q := path.Join(base, path.Join(parts[i:]...))
		var names []string
		for n := range p.files {
			if ok, _ := path.Match(q, n); ok {
				names = append(names, n)
			}
		}
		if len(names) > 0 {
			return names
		}
	}
	return nil
}

// SplitDump splits `nginx -T` output into files: each starts after a line
// "# configuration file <path>:". The first one is the main file.
func SplitDump(dump string) (Files, string, error) {
	files := Files{}
	main := ""
	var cur string
	var b strings.Builder
	flush := func() {
		if cur != "" {
			files[cur] = b.String()
		}
		b.Reset()
	}
	for line := range strings.SplitAfterSeq(dump, "\n") {
		t := strings.TrimRight(line, "\r\n")
		if strings.HasPrefix(t, "# configuration file ") && strings.HasSuffix(t, ":") {
			flush()
			cur = strings.TrimSuffix(strings.TrimPrefix(t, "# configuration file "), ":")
			if main == "" {
				main = cur
			}
			continue
		}
		if cur != "" {
			b.WriteString(line)
		}
	}
	flush()
	if main == "" {
		return nil, "", fmt.Errorf("no \"# configuration file\" header: not nginx -T output")
	}
	return files, main, nil
}
