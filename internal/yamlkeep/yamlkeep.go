// Package yamlkeep restores formatting that yaml.v3 loses when a file is decoded to a node tree
// and written back. Comments survive that round trip but blank lines do not, so an edit such as
// `cellwall ports add` would otherwise delete every blank line in a file the user lays out by hand.
package yamlkeep

import "strings"

// BlankLines returns out with the blank lines of orig put back. A blank line is restored before
// the line that followed it in orig, wherever that line still appears in out (in order). Lines
// that were added or changed by the edit get no blank line; nothing else is touched.
func BlankLines(orig, out []byte) []byte {
	type ln struct {
		text        string
		blankBefore bool
	}
	var src []ln
	blank := false
	for _, l := range strings.Split(string(orig), "\n") {
		l = strings.TrimRight(l, "\r")
		if strings.TrimSpace(l) == "" {
			blank = true
			continue
		}
		src = append(src, ln{strings.TrimRight(l, " \t"), blank})
		blank = false
	}
	if len(src) > 0 {
		src[0].blankBefore = false // leading blank lines are not worth keeping
	}

	var b strings.Builder
	j := 0
	prevBlank := true // nothing before the first line
	for _, l := range strings.Split(strings.TrimSuffix(string(out), "\n"), "\n") {
		trimmed := strings.TrimRight(l, " \t")
		if strings.TrimSpace(l) == "" {
			prevBlank = true
			b.WriteString(l + "\n")
			continue
		}
		// Find this line in the original at or after the cursor, within a short window so an
		// unrelated line elsewhere with identical text cannot pull the cursor far ahead.
		for k := j; k < len(src) && k < j+8; k++ {
			if src[k].text == trimmed {
				if src[k].blankBefore && !prevBlank {
					b.WriteString("\n")
				}
				j = k + 1
				break
			}
		}
		prevBlank = false
		b.WriteString(l + "\n")
	}
	return []byte(b.String())
}
