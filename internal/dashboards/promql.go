package dashboards

import (
	"fmt"
	"strconv"
	"strings"
)

// Matcher is one label matcher of a selector.
type Matcher struct {
	Label string
	Op    string
	Value string
}

// Selector is a metric name with the label matchers that follow it.
type Selector struct {
	Name     string
	Matchers []Matcher
}

// keywords are identifiers that the PromQL grammar reserves. None of them is a metric name.
var keywords = map[string]bool{
	"by": true, "without": true, "on": true, "ignoring": true, "group_left": true, "group_right": true,
	"bool": true, "offset": true, "and": true, "or": true, "unless": true, "atan2": true,
	"inf": true, "nan": true, "start": true, "end": true,
}

// groupWords are the keywords that a parenthesised label list follows.
var groupWords = map[string]bool{
	"by": true, "without": true, "on": true, "ignoring": true, "group_left": true, "group_right": true,
}

// aggregatorBeforeGrouping reports whether the text starts with by or without, followed by a parenthesis.
func aggregatorBeforeGrouping(rest string) bool {
	for _, w := range []string{"by", "without"} {
		if strings.HasPrefix(rest, w) && (len(rest) == len(w) || !isIdentChar(rest[len(w)])) {
			return strings.HasPrefix(strings.TrimLeft(rest[len(w):], " \t\r\n"), "(")
		}
	}
	return false
}

func isIdentStart(c byte) bool {
	return c == '_' || c == ':' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isIdentChar(c byte) bool { return isIdentStart(c) || (c >= '0' && c <= '9') }

type lexer struct {
	s string
	i int
}

func (l *lexer) skipSpace() {
	for l.i < len(l.s) && strings.IndexByte(" \t\r\n", l.s[l.i]) >= 0 {
		l.i++
	}
}

// readString reads a quoted string that starts at the current position.
func (l *lexer) readString() (string, error) {
	q := l.s[l.i]
	start := l.i
	l.i++
	for l.i < len(l.s) {
		c := l.s[l.i]
		if q != '`' && c == '\\' {
			l.i += 2
			continue
		}
		if c == q {
			l.i++
			raw := l.s[start:l.i]
			if q == '\'' {
				raw = `"` + strings.ReplaceAll(raw[1:len(raw)-1], `"`, `\"`) + `"`
			}
			v, err := strconv.Unquote(raw)
			if err != nil {
				return "", fmt.Errorf("bad string %s at %d", raw, start)
			}
			return v, nil
		}
		l.i++
	}
	return "", fmt.Errorf("unterminated string at %d", start)
}

// skipBalanced skips a group that opens at the current position and returns its end.
func (l *lexer) skipBalanced(open, closer byte) error {
	start := l.i
	depth := 0
	for l.i < len(l.s) {
		c := l.s[l.i]
		switch {
		case c == '"' || c == '\'' || c == '`':
			if _, err := l.readString(); err != nil {
				return err
			}
			continue
		case c == open:
			depth++
		case c == closer:
			depth--
			if depth == 0 {
				l.i++
				return nil
			}
		}
		l.i++
	}
	return fmt.Errorf("unbalanced %q at %d", open, start)
}

// readMatchers reads the label matchers of a selector. The position is at the opening brace.
func (l *lexer) readMatchers() ([]Matcher, error) {
	l.i++
	var out []Matcher
	for {
		l.skipSpace()
		if l.i >= len(l.s) {
			return nil, fmt.Errorf("unterminated label matchers")
		}
		if l.s[l.i] == '}' {
			l.i++
			return out, nil
		}
		if l.s[l.i] == ',' {
			l.i++
			continue
		}
		if !isIdentStart(l.s[l.i]) {
			return nil, fmt.Errorf("unexpected %q in label matchers at %d", l.s[l.i], l.i)
		}
		start := l.i
		for l.i < len(l.s) && isIdentChar(l.s[l.i]) {
			l.i++
		}
		label := l.s[start:l.i]
		l.skipSpace()
		op := ""
		for _, cand := range []string{"=~", "!~", "!=", "="} {
			if strings.HasPrefix(l.s[l.i:], cand) {
				op = cand
				break
			}
		}
		if op == "" {
			return nil, fmt.Errorf("no operator after label %q", label)
		}
		l.i += len(op)
		l.skipSpace()
		if l.i >= len(l.s) || (l.s[l.i] != '"' && l.s[l.i] != '\'' && l.s[l.i] != '`') {
			return nil, fmt.Errorf("no string after label %q", label)
		}
		v, err := l.readString()
		if err != nil {
			return nil, err
		}
		out = append(out, Matcher{Label: label, Op: op, Value: v})
	}
}

// Selectors returns every metric selector of a PromQL expression, in order of appearance.
// Function names, keywords, label lists, strings, numbers, durations and Grafana variables are not selectors.
func Selectors(expr string) ([]Selector, error) {
	l := &lexer{s: expr}
	var out []Selector
	parens := 0
	for {
		l.skipSpace()
		if l.i >= len(l.s) {
			break
		}
		c := l.s[l.i]
		switch {
		case c == '"' || c == '\'' || c == '`':
			if _, err := l.readString(); err != nil {
				return nil, err
			}
		case c == '$':
			l.i++
			for l.i < len(l.s) && (isIdentChar(l.s[l.i]) || l.s[l.i] == '{' || l.s[l.i] == '}') {
				l.i++
			}
		case c >= '0' && c <= '9' || c == '.':
			for l.i < len(l.s) && (isIdentChar(l.s[l.i]) || l.s[l.i] == '.') {
				l.i++
			}
		case c == '[':
			if err := l.skipBalanced('[', ']'); err != nil {
				return nil, err
			}
		case c == '{':
			// A selector with no name. It names no metric.
			if _, err := l.readMatchers(); err != nil {
				return nil, err
			}
		case c == '(':
			parens++
			l.i++
		case c == ')':
			parens--
			if parens < 0 {
				return nil, fmt.Errorf("unbalanced ) at %d", l.i)
			}
			l.i++
		case isIdentStart(c):
			start := l.i
			for l.i < len(l.s) && isIdentChar(l.s[l.i]) {
				l.i++
			}
			word := l.s[start:l.i]
			l.skipSpace()
			next := byte(0)
			if l.i < len(l.s) {
				next = l.s[l.i]
			}
			switch {
			case groupWords[word] && next == '(':
				if err := l.skipBalanced('(', ')'); err != nil {
					return nil, err
				}
			case keywords[word]:
			case next == '(':
				// A function name.
			case aggregatorBeforeGrouping(l.s[l.i:]):
				// An aggregation operator, as in sum by (a) (expr).
			default:
				sel := Selector{Name: word}
				if next == '{' {
					ms, err := l.readMatchers()
					if err != nil {
						return nil, err
					}
					sel.Matchers = ms
				}
				out = append(out, sel)
			}
		default:
			l.i++
		}
	}
	if parens != 0 {
		return nil, fmt.Errorf("unbalanced parentheses")
	}
	return out, nil
}

// MetricNames returns the distinct metric names of a PromQL expression, in order of appearance.
func MetricNames(expr string) ([]string, error) {
	sels, err := Selectors(expr)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	for _, s := range sels {
		if !seen[s.Name] {
			seen[s.Name] = true
			out = append(out, s.Name)
		}
	}
	return out, nil
}
