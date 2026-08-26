// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package metaextractexiflib

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/rwcarlsen/goexif/exif"
	"github.com/rwcarlsen/goexif/tiff"
)

// ExifData represents the extracted EXIF metadata
type ExifData struct {
	FilePath string
	Tags     map[string]string
}

// exifWalker implements the Walker interface to extract all EXIF tags
type exifWalker struct {
	tags map[string]string
}

// Walk implements the Walker interface
func (w *exifWalker) Walk(name exif.FieldName, tag *tiff.Tag) error {
	if tag != nil {
		w.tags[string(name)] = tag.String()
	}
	return nil
}

// ExtractExif extracts EXIF data from an image file
func ExtractExif(filePath string) (*ExifData, error) {
	// Open the image file
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %v", err)
	}
	defer f.Close()

	result := &ExifData{
		FilePath: filePath,
		Tags:     make(map[string]string),
	}

	// EXIF is ONE source of image metadata, and its absence is not the absence of metadata.
	//
	// This used to return here the moment exif.Decode failed, which made every source below
	// unreachable for any image without EXIF — including the four raw scans that were already
	// written and already worked. Measured (#456): a 426-byte JPEG carrying an XMP APP1 and no Exif
	// APP1 produced 0 findings, while calling the existing extractXMP on those same bytes returns
	// `XMP_Creator = Employee SSN 449-87-4100`. The code to catch that value was present and simply
	// never ran. A PNG, which keeps its text in chunks and normally has no EXIF at all, was skipped
	// the same way.
	//
	// So a decode failure is now recorded rather than fatal, and the error is only returned at the
	// end if nothing else found anything either — which keeps the contract the caller depends on for
	// genuinely empty or invalid files. See extractImageMetadataWithFallback, which branches on this
	// message.
	x, exifErr := exif.Decode(f)
	if exifErr == nil {
		walker := &exifWalker{tags: result.Tags}
		x.Walk(walker)
	}

	// Extract IPTC, XMP, and other metadata from raw file data
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("error rewinding file: %v", err)
	}
	rawData := make([]byte, 1024*1024) // Read first 1MB
	n, _ := f.Read(rawData)
	if n > 0 {
		// Two of these four are safe to run over ANY bytes and two are not, and the discriminator is
		// the length of the marker they search for.
		//
		// extractIPTC looks for the 2-byte sequence {0x1C, 0x02} and extractJFIFComment for the
		// 2-byte JPEG comment marker 0xFFFE. In compressed data a given 2-byte sequence appears about
		// once every 64KB, so running them over a PNG's IDAT does not find metadata, it finds noise —
		// and the noise becomes a tag, which becomes scannable text. Measured on
		// /System/Library/CoreServices/Dock.app/Contents/Resources/url@2x.png, a 51,700-byte icon:
		// extractJFIFComment emitted 51KB of compressed pixel data as JFIF_Comment, and the
		// validators then reported TWITTER at confidence 100 three times over from handles like
		// "@aE" and "@wVKt" that exist nowhere in the image's metadata. Across 1,200 real images that
		// accounted for 180 of 853 findings.
		//
		// extractXMP searches for "<?xpacket" (9 bytes) and extractPhotoshopResources for
		// "Photoshop 3.0" (13 bytes). Those cannot plausibly collide, and XMP in particular is worth
		// running everywhere: a PNG carries it in an iTXt chunk, which is exactly where this found the
		// value that #456 is about.
		//
		// So the two short-marker scans are gated to the container that DEFINES them, and the two
		// long-marker scans keep running everywhere. This gate is new; before this change the whole
		// block was unreachable for a file without EXIF, which is why the noise had never been seen.
		// Only the JFIF comment scan is gated, and the gate is narrower than my first attempt for a
		// measured reason. Both markers are 2 bytes, but only one of them false-fires in practice:
		// across a 4,000-file real-image sample, gating extractIPTC as well cost 41 findings on TIFFs
		// and one of them was REAL — exiftool confirms By-line "Jonathan Hess" on an Xcode .tiff that
		// this tool reported at PERSON_NAME 92 and would have stopped reporting. IPTC lives in TIFF as
		// well as JPEG, so gating it to JPEG discards a whole format's worth of genuine records to
		// avoid a collision that did not occur.
		//
		// extractJFIFComment is different: its marker sits in front of a 2-byte LENGTH it then trusts,
		// so a chance hit in compressed data yields a large payload rather than nothing. Measured on a
		// 51,700-byte macOS icon it emitted 51KB of pixel data as a comment tag.
		if isJPEG(rawData[:n]) {
			extractJFIFComment(rawData[:n], result.Tags)
		}
		extractIPTC(rawData[:n], result.Tags)
		extractXMP(rawData[:n], result.Tags)
		extractPhotoshopResources(rawData[:n], result.Tags)

		// PNG text lives in chunks, which no byte scan can reach: zTXt is deflated. Dispatched on
		// the SIGNATURE rather than the extension, because an extension is the producer's claim.
		if IsPNG(rawData[:n]) {
			size := int64(0)
			if st, serr := f.Stat(); serr == nil {
				size = st.Size()
			}
			if payload := extractPNGText(f, size, result.Tags); len(payload) > 0 && x == nil {
				// A PNG may carry a real EXIF block in an eXIf chunk, which is the same TIFF stream
				// the decoder above already reads — it just never sees it, because exif.Decode looks
				// for a JPEG APP1 marker. Only consulted when the file-level decode found nothing,
				// so a JPEG's own EXIF is never overridden.
				if px, perr := exif.Decode(bytes.NewReader(payload)); perr == nil {
					px.Walk(&exifWalker{tags: result.Tags})
					x = px
				}
			}
		}
	}

	// Whether anything but the filesystem facts below was found. Counted HERE, before those are
	// added, because FileSize and FileModTime are always present and would make the count useless.
	foundMetadata := len(result.Tags) > 0

	// Extract file system metadata
	if stat, err := os.Stat(filePath); err == nil {
		result.Tags["FileSize"] = fmt.Sprintf("%d bytes", stat.Size())
		result.Tags["FileModTime"] = stat.ModTime().Format("2006:01:02 15:04:05")
	}

	if x == nil {
		// No EXIF at all. Return what the other sources found, or the original decode error if they
		// found nothing — which is the message extractImageMetadataWithFallback branches on.
		if !foundMetadata {
			return nil, fmt.Errorf("no EXIF data found: %v", exifErr)
		}
		return result, nil
	}

	// Calculate GPS coordinates
	lat, long, err := x.LatLong()
	if err == nil {
		result.Tags["GPSLatitudeDecimal"] = fmt.Sprintf("%.6f", lat)
		result.Tags["GPSLongitudeDecimal"] = fmt.Sprintf("%.6f", long)

		// Make sure longitude is negative for west
		if ref, err := x.Get(exif.GPSLongitudeRef); err == nil && ref.String() == "W" {
			result.Tags["GPSLongitudeDecimal"] = fmt.Sprintf("%.6f", -long)
		}
	} else {
		// Try to extract GPS coordinates manually if LatLong() fails
		if latTag, err := x.Get(exif.GPSLatitude); err == nil {
			result.Tags["GPSLatitudeRaw"] = latTag.String()
		}
		if latRefTag, err := x.Get(exif.GPSLatitudeRef); err == nil {
			result.Tags["GPSLatitudeRef"] = latRefTag.String()
		}
		if longTag, err := x.Get(exif.GPSLongitude); err == nil {
			result.Tags["GPSLongitudeRaw"] = longTag.String()
		}
		if longRefTag, err := x.Get(exif.GPSLongitudeRef); err == nil {
			result.Tags["GPSLongitudeRef"] = longRefTag.String()
		}
	}

	// Format GPS altitude
	if alt, err := x.Get(exif.GPSAltitude); err == nil {
		altVal, _ := alt.Rat(0)
		num := altVal.Num().Int64()
		denom := altVal.Denom().Int64()
		altitude := float64(num) / float64(denom)

		// Check if altitude is below sea level
		altRef := "Above Sea Level"
		if altRefTag, err := x.Get(exif.GPSAltitudeRef); err == nil && altRefTag.String() == "1" {
			altitude = -altitude
			altRef = "Below Sea Level"
		}

		result.Tags[string(exif.GPSAltitude)] = fmt.Sprintf("%.2f meters %s", altitude, altRef)
	}

	return result, nil
}

// GetSortedKeys returns the tag keys in alphabetical order, excluding specified fields
func (e *ExifData) GetSortedKeys() []string {
	// Get sorted keys, excluding specific fields
	sortedKeys := make([]string, 0, len(e.Tags))
	for name := range e.Tags {
		// Skip raw GPS coordinates and timestamp
		if name == string(exif.GPSLatitude) ||
			name == string(exif.GPSLongitude) ||
			name == string(exif.GPSTimeStamp) {
			continue
		}
		sortedKeys = append(sortedKeys, name)
	}
	sort.Strings(sortedKeys)
	return sortedKeys
}

// extractIPTC extracts IPTC metadata from raw image data
func extractIPTC(data []byte, tags map[string]string) {
	// Look for IPTC data marker
	iptcMarker := []byte{0x1C, 0x02}
	for i := 0; i < len(data)-10; i++ {
		if bytes.HasPrefix(data[i:], iptcMarker) {
			// Found IPTC record, extract basic fields
			recordType := data[i+2]
			if i+4 < len(data) {
				length := int(data[i+3])<<8 | int(data[i+4])
				if i+5+length <= len(data) {
					value := string(data[i+5 : i+5+length])
					// Skip corrupted or non-printable data
					if !isPrintableString(value) {
						continue
					}
					switch recordType {
					case 0x50: // By-line (Author)
						tags["IPTC_Byline"] = value
					case 0x37: // Date Created
						tags["IPTC_DateCreated"] = value
					case 0x3C: // Time Created
						tags["IPTC_TimeCreated"] = value
					case 0x78: // Caption
						tags["IPTC_Caption"] = value
					}
				}
			}
		}
	}
}

// extractXMP extracts XMP metadata from raw image data
func extractXMP(data []byte, tags map[string]string) {
	// Look for XMP packet
	xmpStart := bytes.Index(data, []byte("<?xpacket"))
	if xmpStart == -1 {
		return
	}
	xmpEnd := bytes.Index(data[xmpStart:], []byte("<?xpacket end"))
	if xmpEnd == -1 {
		return
	}
	xmpData := string(data[xmpStart : xmpStart+xmpEnd])

	// Extract common XMP fields using regex
	extractXMPField(xmpData, `dc:creator[^>]*>([^<]+)`, "XMP_Creator", tags)
	extractXMPField(xmpData, `xmp:CreatorTool[^>]*>([^<]+)`, "XMP_CreatorTool", tags)
	extractXMPField(xmpData, `photoshop:DateCreated[^>]*>([^<]+)`, "XMP_DateCreated", tags)
}

// extractXMPField extracts a specific XMP field using regex
func extractXMPField(xmpData, pattern, fieldName string, tags map[string]string) {
	re := regexp.MustCompile(pattern)
	if match := re.FindStringSubmatch(xmpData); len(match) > 1 {
		tags[fieldName] = strings.TrimSpace(match[1])
	}
}

// extractJFIFComment extracts the JPEG COM segment, by WALKING the segment chain.
//
// The previous version scanned every byte position for the pair 0xFF 0xFE and trusted the two bytes
// behind it as a length. A given byte pair turns up about once every 64KB of compressed data, so on a
// real JPEG that finds noise, and the noise is then handed to the validators as document text.
//
// Measured on an Apple-shipped asset,
// /Applications/Numbers.app/Contents/SharedSupport/DocumentResources/50/9f5178abe0a74d6f0a905b2974c7c7a203b965.jpeg
// (139,103 bytes): the file has NO COM segment and NO Exif APP1, and exactly one 0xFFFE in it -- at
// offset 557, inside the Display P3 ICC profile carried in APP2, which spans bytes 2 to 566. It
// declares 59,392 bytes, so 59KB of ICC tail, quantisation tables and entropy-coded scan were emitted
// as JFIF_Comment. Extracted text went 210 -> 59,599 characters and the validators reported FIVE
// SOCIAL_MEDIA TWITTER findings at HIGH 100/91 -- @hf, @K_pIa, @am, @E4, @L_ -- for handles present
// nowhere in the file.
//
// The consequence is not a cosmetic false positive. Those findings drive the image redactor, which
// decodes and re-encodes the picture, so a "redacted" copy was written for a file holding nothing:
// 139,103 -> 95,213 bytes, 418,816 of 487,080 decoded pixel bytes different (85.99%, max channel delta
// 60), and the ICC profile GONE. A lossy redactor must act on "this part holds a reported value", and
// here the reported value was an artefact of this reader. Before #480 the branch was unreachable for an
// image without Exif, which is why the defect surfaced when that returned-early behaviour was fixed.
//
// Walking is the fix rather than a tighter length check, because no check on the length can tell a
// marker from two bytes that merely look like one. A COM segment is a COM segment only if the chain
// leads to it.
func extractJFIFComment(data []byte, tags map[string]string) {
	// Every JPEG starts with SOI. Without it this is not a segment chain and there is nothing to walk.
	if len(data) < 4 || data[0] != 0xFF || data[1] != 0xD8 {
		return
	}

	for i := 2; i+1 < len(data); {
		if data[i] != 0xFF {
			return // not positioned on a marker: the chain is broken, so stop rather than guess
		}
		marker := data[i+1]

		switch {
		case marker == 0xFF:
			// Fill bytes are legal before a marker; skip one and re-examine.
			i++
			continue
		case marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7):
			// TEM and the restart markers carry no payload and no length.
			i += 2
			continue
		case marker == 0xD9:
			return // EOI
		}

		if i+3 >= len(data) {
			return
		}
		// A segment length INCLUDES its own two bytes, so the payload is length-2 bytes long.
		length := int(data[i+2])<<8 | int(data[i+3])
		if length < 2 || i+2+length > len(data) {
			return // truncated or nonsensical: stop rather than read past the segment
		}

		if marker == 0xFE {
			comment := string(data[i+4 : i+2+length])
			if strings.TrimSpace(comment) != "" {
				tags["JFIF_Comment"] = comment
				return
			}
		}

		if marker == 0xDA {
			// SOS. Entropy-coded data follows, in which 0xFF bytes are stuffed rather than
			// markers, so nothing beyond here is addressable by walking -- and that is exactly
			// the region the old byte scan was reading.
			return
		}
		i += 2 + length
	}
}

// extractPhotoshopResources extracts Photoshop resource blocks
func extractPhotoshopResources(data []byte, tags map[string]string) {
	// Look for Photoshop 3.0 signature
	psMarker := []byte("Photoshop 3.0")
	if idx := bytes.Index(data, psMarker); idx != -1 {
		tags["Photoshop_Resources"] = "Present"
		// Look for common resource blocks like layer names, etc.
		if layerIdx := bytes.Index(data[idx:], []byte("8BIM")); layerIdx != -1 {
			tags["Photoshop_8BIM"] = "Present"
		}
	}
}

// isPrintableString checks if a string contains only printable characters
func isPrintableString(s string) bool {
	for _, r := range s {
		if r < 32 || r > 126 {
			return false
		}
	}
	return len(s) > 0
}
