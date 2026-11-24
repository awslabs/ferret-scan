// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package phone

import "strings"

// frHexRunLimit is the length, in two-character tokens, from which a run of them on one line is a
// hex dump and not a list of French numbers. Two numbers written one after the other are 10 tokens;
// a dump line (xxd, hexdump -C, an OpenSSL or Go test fixture) carries 16.
const frHexRunLimit = 11

func isHexByte(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

// pairAt reports whether line[i:i+2] is two hex characters standing alone: not glued to another
// alphanumeric on either side.
func pairAt(line string, i int) bool {
	if i < 0 || i+2 > len(line) || !isHexByte(line[i]) || !isHexByte(line[i+1]) {
		return false
	}
	return (i == 0 || !isWordByteASCII(line[i-1])) && (i+2 == len(line) || !isWordByteASCII(line[i+2]))
}

// isHexOffset reports whether s is the offset column of a hex dump: seven or eight hex digits.
func isHexOffset(s string) bool {
	if len(s) < 7 || len(s) > 8 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isHexByte(s[i]) {
			return false
		}
	}
	return true
}

// frPairsContinue reports whether the FR_National match line[start:end] ("0X" and four pairs, one
// separator) is a stretch of a longer chain and so not a French number (#1052):
//
//   - written with dots or dashes, another digit group joined by a separator after it
//     ("01.42.34.56.78.90": a serial or a version) or before it ("2006.01.02.15.04.05": a timestamp;
//     "01:02-03-04-05-06": a MAC address). A full stop that ends a sentence is not followed by a digit;
//   - written with any separator, a run of eleven or more pairs joined by that separator, which is a
//     hex dump line. Letters count (50 4b 03 04 ...), so a dump is recognised however few of its bytes
//     are digits. Ten tokens are the two numbers a list of them can hold. A shorter last line of a
//     dump is recognised by its offset column ("00000170  02 02 02 04 02 05 02 06  02").
//
// shortcut: a space-separated number inside a longer plain list of digit pairs is reported (the
// compact form is too); upgrade if a corpus shows prose that does it.
func frPairsContinue(line string, start, end int) bool {
	sep := line[start+2]
	if sep != ' ' {
		if end+1 < len(line) && line[end] == sep && isDigitByte(line[end+1]) {
			return true
		}
		if start >= 2 && (line[start-1] == '.' || line[start-1] == '-' || line[start-1] == ':') && isDigitByte(line[start-2]) {
			return true
		}
	}
	run := 5
	// hexdump -C and Go's test fixtures put a second space between the eighth and ninth byte.
	width := func(i int, step int) int { // separator width starting at i, walking by step; 0 if none
		if i < 0 || i >= len(line) || line[i] != sep {
			return 0
		}
		if sep == ' ' && i+step >= 0 && i+step < len(line) && line[i+step] == ' ' {
			return 2
		}
		return 1
	}
	first := start
	for run < frHexRunLimit { // the walk stops at the limit, so a line of pairs costs O(1) per match
		g := width(first-1, -1)
		if g == 0 || !pairAt(line, first-g-2) {
			break
		}
		first -= g + 2
		run++
	}
	for i := end; run < frHexRunLimit; {
		g := width(i, 1)
		if g == 0 || !pairAt(line, i+g) {
			break
		}
		i += g + 2
		run++
	}
	if run >= frHexRunLimit {
		return true
	}
	return sep == ' ' && first > 0 && isHexOffset(strings.TrimSpace(line[:first]))
}
