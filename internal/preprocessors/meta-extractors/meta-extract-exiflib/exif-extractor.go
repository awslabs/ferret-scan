// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package metaextractexiflib

import (
	"bytes"
	"fmt"
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

	// Decode EXIF data
	x, err := exif.Decode(f)
	if err != nil {
		return nil, fmt.Errorf("no EXIF data found: %v", err)
	}

	// Create result structure
	result := &ExifData{
		FilePath: filePath,
		Tags:     make(map[string]string),
	}

	// Create a custom walker to extract all available tags
	walker := &exifWalker{tags: result.Tags}
	x.Walk(walker)

	// Extract IPTC, XMP, and other metadata from raw file data
	f.Seek(0, 0)
	rawData := make([]byte, 1024*1024) // Read first 1MB
	n, _ := f.Read(rawData)
	if n > 0 {
		extractIPTC(rawData[:n], result.Tags)
		extractXMP(rawData[:n], result.Tags)
		extractJFIFComment(rawData[:n], result.Tags)
		extractPhotoshopResources(rawData[:n], result.Tags)
	}

	// Extract file system metadata
	if stat, err := os.Stat(filePath); err == nil {
		result.Tags["FileSize"] = fmt.Sprintf("%d bytes", stat.Size())
		result.Tags["FileModTime"] = stat.ModTime().Format("2006:01:02 15:04:05")
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

// extractJFIFComment extracts JFIF comment segments
func extractJFIFComment(data []byte, tags map[string]string) {
	// Look for JPEG comment marker (0xFFFE)
	for i := 0; i < len(data)-4; i++ {
		if data[i] == 0xFF && data[i+1] == 0xFE {
			length := int(data[i+2])<<8 | int(data[i+3])
			if i+4+length <= len(data) && length > 0 {
				comment := string(data[i+4 : i+4+length])
				if strings.TrimSpace(comment) != "" {
					tags["JFIF_Comment"] = comment
					break
				}
			}
		}
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
