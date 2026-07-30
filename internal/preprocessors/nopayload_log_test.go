// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package preprocessors

import (
	"bytes"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/observability"
	audiolib "github.com/awslabs/ferret-scan/v2/internal/preprocessors/meta-extractors/meta-extract-audiolib"
	exiflib "github.com/awslabs/ferret-scan/v2/internal/preprocessors/meta-extractors/meta-extract-exiflib"
	pdflib "github.com/awslabs/ferret-scan/v2/internal/preprocessors/meta-extractors/meta-extract-pdflib"
)

// debugObserver returns an observer whose debug output lands in buf.
func debugObserver(buf *bytes.Buffer) *observability.StandardObserver {
	debugObs := observability.NewDebugObserver(buf)
	observer := debugObs.StandardObserver
	observer.DebugObserver = debugObs
	return observer
}

// assertNoPayload fails for every sentinel found in the captured log.
func assertNoPayload(t *testing.T, log *bytes.Buffer, sentinels, mustContain []string) {
	t.Helper()
	got := log.String()

	// Non-vacuity: an empty log, or one that skipped the site under test, would
	// pass the sentinel loop while proving nothing.
	if log.Len() == 0 {
		t.Fatal("no debug output captured, so this test cannot detect a leak")
	}
	for _, want := range mustContain {
		if !strings.Contains(got, want) {
			t.Errorf("log path %q was not exercised, so this test does not cover it.\n--- log ---\n%s", want, got)
		}
	}
	for _, s := range sentinels {
		if strings.Contains(got, s) {
			t.Errorf("document content %q leaked into the observability log (BSC4).\n--- log ---\n%s", s, got)
		}
	}
}

// TestImageMetadataNoPayloadInDebugLog is the BSC4 gate for the image
// preprocessor. Its GPS debug loop logged every GPS tag's VALUE — a coordinate
// is location PII that the metadata validator reports as a finding, so scanning
// a geotagged photo with --debug wrote the subject's location to stderr.
//
// The tags are set directly rather than extracted from a JPEG fixture: these are
// in-package methods over a plain map, and validateFilePath rejects temp-dir
// paths for some extractors anyway.
func TestImageMetadataNoPayloadInDebugLog(t *testing.T) {
	var log bytes.Buffer
	imp := NewImageMetadataPreprocessor()
	imp.SetObserver(debugObserver(&log))

	exifData := &exiflib.ExifData{
		FilePath: "nopayload.jpg",
		Tags: map[string]string{
			"GPSLatitudeDecimal":  "36.3506111",
			"GPSLongitudeDecimal": "-94.2088333",
			"GPSAltitude":         "313.7 metres",
			"GPSLatitudeRef":      "N",
			"GPSDateStamp":        "2026:07:04",
			"Make":                "ZyxwvutCam",
			"Model":               "Qwertyuiop X900",
			"ImageDescription":    "patient 219-09-9996",
		},
	}

	// formatImageMetadata deletes the consolidated GPS keys, so run the
	// presence-only logger first while the tags are still there.
	imp.logSuccessfulProcessing("nopayload.jpg", exifData)
	imp.formatImageMetadata(exifData)

	assertNoPayload(t, &log,
		[]string{
			"36.3506111", "94.2088333", "313.7", "2026:07:04",
			"ZyxwvutCam", "Qwertyuiop", "219-09-9996",
		},
		[]string{
			"GPS tag found: GPSAltitude",
			"Consolidated GPS coordinates: [HIDDEN]",
			"Camera info present",
			"GPS coordinates found: [HIDDEN]",
		})
}

// TestImageMetadataGPSLogOrderIsStable pins the determinism half of the same
// fix: the GPS loop used to range the tag map directly, so the debug lines came
// out in a different order on every run. Map iteration order is randomized per
// range, so repeating the call is a real (if probabilistic) check.
func TestImageMetadataGPSLogOrderIsStable(t *testing.T) {
	tagsOf := func() map[string]string {
		return map[string]string{
			"GPSLatitudeRef":     "N",
			"GPSLongitudeRef":    "W",
			"GPSAltitude":        "313.7 metres",
			"GPSDateStamp":       "2026:07:04",
			"GPSImgDirection":    "12.5",
			"GPSSpeed":           "0",
			"GPSSpeedRef":        "K",
			"GPSDestBearing":     "90",
			"GPSInfoIFDPointer":  "878",
			"GPSImgDirectionRef": "T",
		}
	}

	var first string
	for i := 0; i < 20; i++ {
		var log bytes.Buffer
		imp := NewImageMetadataPreprocessor()
		imp.SetObserver(debugObserver(&log))
		imp.formatImageMetadata(&exiflib.ExifData{FilePath: "x.jpg", Tags: tagsOf()})

		var lines []string
		for _, l := range strings.Split(log.String(), "\n") {
			if strings.Contains(l, "GPS tag found:") {
				lines = append(lines, l)
			}
		}
		if len(lines) == 0 {
			t.Fatal("no GPS tag lines logged, so this test cannot detect reordering")
		}
		joined := strings.Join(lines, "\n")
		if i == 0 {
			first = joined
			continue
		}
		if joined != first {
			t.Fatalf("GPS debug log order varies between runs (run %d):\n--- first ---\n%s\n--- run %d ---\n%s", i, first, i, joined)
		}
	}
}

// TestAudioMetadataNoPayloadInDebugLog is the BSC4 gate for the audio
// preprocessor: Artist/Title/Album are document content the metadata validator
// scans for PII (a personal name in an Artist tag is a finding).
func TestAudioMetadataNoPayloadInDebugLog(t *testing.T) {
	var log bytes.Buffer
	amp := NewAudioMetadataPreprocessor()
	amp.SetObserver(debugObserver(&log))

	amp.logSuccessfulProcessing("nopayload.mp3", &audiolib.AudioMetadata{
		Artist: "Zyxwvut Qwertyuiop",
		Title:  "Interview with 219-09-9995",
		Album:  "Acmehealthcorp Sessions",
		Year:   2026,
	})

	assertNoPayload(t, &log,
		[]string{"Zyxwvut", "Qwertyuiop", "219-09-9995", "Acmehealthcorp"},
		[]string{"Track info found: artist [HIDDEN]", "Album info: [HIDDEN]"})
}

// TestPDFMetadataNoPayloadInDebugLog is the BSC4 gate for the PDF preprocessor:
// Producer strings routinely carry internal tool and host names.
func TestPDFMetadataNoPayloadInDebugLog(t *testing.T) {
	var log bytes.Buffer
	pmp := NewPDFMetadataPreprocessor()
	pmp.SetObserver(debugObserver(&log))

	pmp.buildPDFMetadataText(&pdflib.Metadata{
		Producer:   "ZyxwvutPDF 9.1 on qwertyuiop-build01.corp.internal",
		Title:      "Chart",
		Properties: map[string]string{},
	})

	assertNoPayload(t, &log,
		[]string{"ZyxwvutPDF", "qwertyuiop-build01", "corp.internal"},
		[]string{"Adding Producer to metadata content: [HIDDEN]"})
}
