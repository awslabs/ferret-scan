// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package replacement

import (
	"crypto/rand"
	"strconv"
	"testing"
)

// luhnValid is the Luhn mod-10 check the nationalid validator's validSIN applies
// (internal/validators/nationalid/checks.go). It is written out here, independent of luhnCheck, so
// the test does not grade the generator with the generator's own arithmetic.
func luhnValid(digits string) bool {
	sum, double := 0, false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if double {
			if d *= 2; d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

// A synthetic SSN is nine digits that must not re-detect as anything else (#1020). A SIN is nine
// digits that pass Luhn with a leading digit that is not 0 or 8; the 666 and 9xx areas ssnDigits
// draws lead with 6 and 9, so about one draw in ten was a Luhn-valid SIN.
func TestSSNDigitsIsNeverALuhnValidSIN(t *testing.T) {
	const draws = 10000
	s := &source{r: rand.Reader}
	sinLeading := 0 // draws a SIN validator would otherwise look at: non-vacuity floor
	for i := 0; i < draws; i++ {
		d := ssnDigits(s)
		if len(d) != 9 {
			t.Fatalf("draw %d: %q is not nine digits", i, d)
		}
		if d[0] != '0' && d[0] != '8' {
			sinLeading++
		}
		if luhnValid(d) {
			t.Fatalf("draw %d: %q passes Luhn, so a SIN validator accepts it (leading %c)", i, d, d[0])
		}
		// The rules ssnDigits already kept: 000 and 666 areas, or a 9xx area with a group in 01-49.
		area, group := d[:3], d[3:5]
		g, _ := strconv.Atoi(group)
		switch {
		case area == "000" || area == "666":
		case area[0] == '9' && g >= 1 && g <= 49:
		default:
			t.Fatalf("draw %d: %q has area %s group %s, outside the never-issued, never-ITIN set", i, d, area, group)
		}
	}
	if sinLeading < draws/4 {
		t.Fatalf("only %d of %d draws lead with a SIN-eligible digit: the test is not exercising the case", sinLeading, draws)
	}
}
