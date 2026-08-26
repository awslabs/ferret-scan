// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package metaextractvideolib

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	// isobmff is a pure-standard-library ISO base media container parser — its own package
	// comment states that nothing about redaction belongs in it — and it owns the spec-derived
	// definition of an ISO 6709 position string. The extractor shares that definition rather
	// than keeping a second copy, because the two sides disagreeing about what a position looks
	// like is exactly the defect being fixed here (#399). Its home under internal/redactors is
	// historical; moving it somewhere neutral is a separate, purely mechanical change.
	"github.com/awslabs/ferret-scan/v2/internal/redactors/isobmff"
)

// VideoMetadata represents extracted video file metadata
type VideoMetadata struct {
	// File information
	Filename string
	FileSize int64
	ModTime  time.Time
	MimeType string

	// Video-specific metadata
	Duration  time.Duration
	Width     int
	Height    int
	FrameRate float64
	Codec     string

	// Common metadata fields
	Title        string
	Description  string
	Author       string
	Creator      string
	Copyright    string
	CreatedDate  time.Time
	ModifiedDate time.Time

	// Location data
	GPSLatitude  float64
	GPSLongitude float64
	GPSAltitude  float64
	Location     string

	// Device information
	CameraMake  string
	CameraModel string
	Software    string

	// Additional properties
	Properties map[string]string

	// decodedAppleKeys records which com.apple.quicktime.* keys were read properly out of a
	// keys/ilst pair, so searchAppleMetadataInData's raw text scrape can stand down for those.
	//
	// Unexported and deliberately NOT a property: the marker must not itself become emitted content.
	// An earlier version used the presence of the emitted QuickTime_* property as the signal, which
	// forced every decoded value to be written twice — once as its typed field and once as a
	// property — and ToProcessedContent emits both, so one value in the file produced TWO findings.
	decodedAppleKeys map[string]bool

	// assetKeyCounts is how many properties each 3GPP asset field has already taken, so a unique
	// key is a counter increment rather than a scan for the first free number.
	//
	// Unexported, like decodedAppleKeys, because it is bookkeeping and must not become emitted
	// content. The probing version it replaces was quadratic — see uniqueAssetKey.
	assetKeyCounts map[string]int

	// ExtractionWarning is a payload-free note that extraction finished but covered less than the
	// whole file, so a value may be missing. It carries box types, byte offsets and limit
	// constants only — never a metadata value, and never matched text.
	//
	// Before this existed the walk gave up on a bare `break` and returned a nil error, so a file
	// whose metadata was never reached was reported as a complete, clean scan. AudioMetadata has
	// carried the equivalent field for the same reason.
	ExtractionWarning string
}

// noteTruncation records the FIRST reason coverage was lost and keeps it.
//
// First wins rather than last: the earliest failure is the one that explains the others, and a
// later note would otherwise overwrite the cause with a symptom.
func noteTruncation(metadata *VideoMetadata, note string) {
	if metadata.ExtractionWarning == "" {
		metadata.ExtractionWarning = note
	}
}

// Constants for MP4 parsing
const (
	// MaxFileSize is the extractor's own ceiling. It sits above the router's 100MB gate, which
	// refuses the file first, so it is effectively unreachable on the CLI path.
	MaxFileSize   = 500 * 1024 * 1024 // 500MB limit
	BoxHeaderSize = 8                 // 4 bytes size + 4 bytes type

	// ExtendedBoxSize is the header length when a box declares a 64-bit size (size == 1).
	ExtendedBoxSize = 16

	// MaxMoovParse bounds the ONE allocation this extractor makes: the moov payload it parses.
	// Memory is therefore O(min(|moov|, MaxMoovParse)) and independent of the file's size.
	//
	// 32MB is measured headroom rather than a guess. The router refuses anything over 100MB before
	// extraction runs, and a real moov is a fraction of its file — 0.14%, 0.27% and 0.39% across
	// the videos on the machine this was written on — so a 100MB file's moov is a few hundred
	// kilobytes. A moov beyond this is clamped and DISCLOSED, never silently truncated.
	MaxMoovParse = 32 * 1024 * 1024

	// MaxTopLevelBoxes bounds the walk's work so a file made of millions of tiny boxes cannot turn
	// a scan into a CPU amplifier. A well-formed movie has a handful; a fragmented one (DASH/CMAF,
	// a moof+mdat pair per fragment) can legitimately have tens of thousands.
	//
	// 1<<20 matches the atom budget the redactor's walk already uses, so the two sides give up at
	// the same point. Measured cost is ~1.3µs per box — 100k boxes walk in 0.13s — so this ceiling
	// is ~1.4s in the worst case, well inside ProcessingTimeout. A tighter 100k ceiling was tried
	// first and rejected: it is reachable in an 800KB file, and it LOST a finding that the previous
	// code found, which is the wrong direction to trade even for a disclosure.
	MaxTopLevelBoxes = 1 << 20

	ProcessingTimeout = 30 * time.Second // 30 second timeout
)

// videoContainerExtensions is the single list of containers this extractor reads, so CanProcessVideo
// and GetSupportedVideoFormats cannot disagree — they were two independent literals.
//
// `.3gp` and `.3g2` are the same ISO base media container as `.mp4` with a different brand, and were
// absent from both. The consequence was not a refusal but a SILENT one: a `.3gp` carrying an SSN in
// its description reported `No matches found.` at exit 0, and `--fail-on-incomplete` also exited 0
// with nothing in the not-examined block, so the value was neither reported nor redacted and nothing
// said so. Verified with a real ffmpeg-written file that exiftool reads the value out of.
//
// The extension list is what admits a file this far; the parse itself is brand-agnostic, which is why
// adding the two entries is sufficient rather than a starting point.
var videoContainerExtensions = map[string]bool{
	".mp4": true,
	".m4v": true,
	".mov": true,
	".3gp": true,
	".3g2": true,
}

// errDeclaredOverrun marks a box whose declared size runs past the real end of the file.
//
// Its own sentinel because it is the one header error worth recovering from: the bytes up to the
// real end are still worth parsing, which turns a truncated download into a partial result plus a
// disclosure rather than nothing at all.
var errDeclaredOverrun = errors.New("box declares more bytes than the file holds")

// ExtractVideoMetadata extracts metadata from video files with resource limits
func ExtractVideoMetadata(filePath string) (*VideoMetadata, error) {
	cleanPath := filepath.Clean(filePath)
	if !filepath.IsAbs(cleanPath) {
		return nil, errors.New("relative paths are not allowed")
	}
	return ExtractVideoMetadataWithContext(context.Background(), cleanPath)
}

// ExtractVideoMetadataWithContext extracts metadata from video files with context and resource limits
func ExtractVideoMetadataWithContext(ctx context.Context, filePath string) (*VideoMetadata, error) {
	// Create processing context with timeout
	processCtx, cancel := context.WithTimeout(ctx, ProcessingTimeout)
	defer cancel()

	// Get file info
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return nil, NewVideoProcessingError(filePath, "file_access", "failed to get file info", err)
	}

	// Check file size limit
	if fileInfo.Size() > MaxFileSize {
		return nil, NewVideoProcessingError(filePath, "file_size",
			fmt.Sprintf("file too large: %d bytes (max %d)", fileInfo.Size(), MaxFileSize), nil)
	}

	// Initialize metadata structure
	metadata := &VideoMetadata{
		Filename:   filepath.Base(filePath),
		FileSize:   fileInfo.Size(),
		ModTime:    fileInfo.ModTime(),
		Properties: make(map[string]string),
	}

	// Determine MIME type based on extension
	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".mp4", ".m4v":
		metadata.MimeType = "video/mp4"
	case ".mov":
		metadata.MimeType = "video/quicktime"
	case ".3gp":
		metadata.MimeType = "video/3gpp"
	case ".3g2":
		metadata.MimeType = "video/3gpp2"
	default:
		metadata.MimeType = "video/unknown"
	}

	// Use optimized reader for better performance
	optimizedReader, err := NewOptimizedVideoReader(filePath)
	if err != nil {
		return nil, NewVideoProcessingError(filePath, "file_access", "failed to create optimized reader", err)
	}
	defer optimizedReader.Close()

	// Parse MP4/MOV container with optimized reading
	err = parseMP4ContainerOptimized(processCtx, optimizedReader, metadata)
	if err != nil {
		if processCtx.Err() == context.DeadlineExceeded {
			return nil, NewVideoProcessingError(filePath, "timeout", "processing timeout exceeded", err)
		}
		return nil, NewVideoProcessingError(filePath, "parsing", "failed to parse container", err)
	}

	// Enhanced metadata extraction for comprehensive analysis
	searchForGPSInMetadata(metadata)
	searchForCombinedMetadata(filePath, metadata)

	return metadata, nil
}

// searchForGPSInMetadata searches for GPS data in all metadata properties and values.
//
// This is a heuristic scrape: it guesses at coordinates from any property whose
// key or value merely mentions "location"/"gps"/"deg", or whose value carries two
// or more signs. Both parse helpers write the SCALAR GPSLatitude/GPSLongitude/
// GPSAltitude fields, which are emitted as the single "GPS_Coordinates" line, so
// two candidate properties compete for one output value. Iterating the map
// directly made that competition a coin flip: the emitted coordinate could differ
// run to run for the same file. Properties are therefore walked in sorted key
// order, and the first complete pair wins.
//
// First-complete-wins also protects precision, which a bare sort would not. By
// the time this runs, the container parse has already handled the authoritative
// '©xyz' GPS atom, so a real coordinate may already be present. The properties
// scanned here are mostly free text — the udta string boxes (Information,
// Warning, URL, Lyrics, Source, ...) and unrecognized four-character ilst tags —
// and any of them can mention "deg" or carry two signs and parse into a
// meaningless coordinate. Sorting alone would still let such a value overwrite
// the atom's; stopping at the first complete pair keeps the better value instead
// of merely making the worse one repeatable.
func searchForGPSInMetadata(metadata *VideoMetadata) {
	keys := make([]string, 0, len(metadata.Properties))
	for key := range metadata.Properties {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	// Search in existing properties
	for _, key := range keys {
		if metadata.GPSLatitude != 0 && metadata.GPSLongitude != 0 {
			// A complete coordinate is already known (from the container atom or
			// an earlier property); do not let a later guess overwrite it.
			return
		}
		value := metadata.Properties[key]

		if strings.Contains(strings.ToLower(key), "location") ||
			strings.Contains(strings.ToLower(key), "gps") ||
			strings.Contains(strings.ToLower(value), "location") ||
			strings.Contains(strings.ToLower(value), "deg") {
			parseGPSString(value, metadata)
		}

		// Check for ISO 6709 format (±DD.DDDD±DDD.DDDD±AAA.AAA)
		if strings.Contains(value, "+") && strings.Contains(value, "-") &&
			(strings.Count(value, "+")+strings.Count(value, "-")) >= 2 {
			parseISO6709Location(value, metadata)
		}
	}
}

// searchForCombinedMetadata searches for both Apple QuickTime and additional metadata patterns in raw file data
func searchForCombinedMetadata(filePath string, metadata *VideoMetadata) {
	processFileChunks(filePath, 5*1024*1024, func(data []byte) {
		if isValidUTF8Subset(data) {
			dataStr := string(data)
			searchAppleMetadataInData(dataStr, metadata)
			searchMetadataPatternsInData(dataStr, metadata)
		}
	})
}

// processFileChunks reads a file in chunks and applies a processing function to each chunk
func processFileChunks(filePath string, maxSearchBytes int64, processFunc func([]byte)) {
	file, err := os.Open(filePath)
	if err != nil {
		return
	}
	defer file.Close()

	buffer := make([]byte, 64*1024) // 64KB chunks
	var accumulated []byte
	totalRead := int64(0)

	for {
		if totalRead >= maxSearchBytes {
			break
		}

		n, err := file.Read(buffer)
		if n == 0 {
			break
		}

		totalRead += int64(n)
		accumulated = append(accumulated, buffer[:n]...)

		if len(accumulated) > 32*1024 {
			accumulated = accumulated[len(accumulated)-32*1024:]
		}

		processFunc(accumulated)

		if err == io.EOF {
			break
		}
		if err != nil {
			return
		}
	}
}

// VideoProcessingError represents an error during video processing
type VideoProcessingError struct {
	FilePath    string
	ErrorType   string
	Message     string
	Err         error
	Recoverable bool
	Context     map[string]any
}

func (e *VideoProcessingError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("video processing failed for %s (%s): %s - %v",
			e.FilePath, e.ErrorType, e.Message, e.Err)
	}
	return fmt.Sprintf("video processing failed for %s (%s): %s",
		e.FilePath, e.ErrorType, e.Message)
}

func (e *VideoProcessingError) Unwrap() error {
	return e.Err
}

func (e *VideoProcessingError) IsRecoverable() bool {
	return e.Recoverable
}

func (e *VideoProcessingError) WithContext(key string, value any) *VideoProcessingError {
	if e.Context == nil {
		e.Context = make(map[string]any)
	}
	e.Context[key] = value
	return e
}

// NewVideoProcessingError creates a new video processing error
func NewVideoProcessingError(filePath, errorType, message string, err error) *VideoProcessingError {
	return &VideoProcessingError{
		FilePath:    filePath,
		ErrorType:   errorType,
		Message:     message,
		Err:         err,
		Recoverable: isVideoErrorRecoverable(errorType),
		Context:     make(map[string]any),
	}
}

// isVideoErrorRecoverable determines if a video error is recoverable
func isVideoErrorRecoverable(errorType string) bool {
	switch errorType {
	case "file_access", "timeout":
		return true
	case "file_size", "unsupported_format", "parsing":
		return false
	default:
		return false
	}
}

// parseFtypBox parses the file type box
func parseFtypBox(data []byte, metadata *VideoMetadata) error {
	if len(data) < 8 {
		return fmt.Errorf("ftyp box too small")
	}

	majorBrand := string(data[0:4])
	metadata.Properties["MajorBrand"] = majorBrand

	// Set codec based on major brand
	switch majorBrand {
	case "mp41", "mp42":
		metadata.Codec = "MPEG-4"
	case "qt  ":
		metadata.Codec = "QuickTime"
	case "M4V ":
		metadata.Codec = "iTunes Video"
	case "3gp4", "3gp5", "3gp6", "3gp7", "3gp8", "3gp9", "3gr6", "3gs6", "3ge6", "3gg6":
		// The 3GPP brands. ffmpeg writes 3gp4 for .3gp; the rest are the release and profile
		// variants defined in 3GPP TS 26.244, listed from the spec rather than from what one
		// fixture happened to contain.
		metadata.Codec = "3GPP"
	case "3g2a", "3g2b", "3g2c":
		// 3GPP2, per 3GPP2 C.S0050.
		metadata.Codec = "3GPP2"
	default:
		metadata.Codec = majorBrand
	}

	return nil
}

// parseMoovBox parses the movie box containing metadata
func parseMoovBox(data []byte, metadata *VideoMetadata) error {
	return parseMoovBoxWithContext(context.Background(), data, metadata)
}

// parseMoovBoxWithContext parses the movie box containing metadata with context
func parseMoovBoxWithContext(ctx context.Context, data []byte, metadata *VideoMetadata) error {
	offset := 0

	for offset < len(data) {
		// Check context for cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if offset+BoxHeaderSize > len(data) {
			break
		}

		// readChildHeader carries the bounds check this walker used to spell out inline — a child
		// declaring more bytes than the box holds sliced out of range, and `[moov > mvhd declaring
		// 64 with 8 bytes present]` panicked with "slice bounds out of range [:64] with capacity
		// 32", caught by the router's recover() so the process survived but video metadata
		// extraction was abandoned and its findings lost (#377). It also honours the two special
		// size words, which this walker did not: a largesize or size-0 udta at moov level was
		// silently skipped, and a comment carried in one produced no finding.
		boxType, payloadStart, payloadEnd, ok := readChildHeader(data, offset)
		if !ok {
			break
		}
		size := payloadEnd - offset

		boxData := data[payloadStart:payloadEnd]

		switch boxType {
		case "mvhd":
			err := parseMvhdBox(boxData, metadata)
			if err != nil {
				// Non-fatal: this child is unreadable, the rest of the box is not. Deliberately
				// NOT `continue` — that skipped the `offset += int(size)` at the foot of the
				// loop, so the walk stopped advancing and spun until the 30s processing timeout
				// cancelled it. Measured: a 16-byte `[moov > mvhd(8, empty)]` burned 30s of CPU,
				// and a 24-byte `[moov > trak > tkhd(empty)]` did the same through the trak
				// walker — so a directory of tiny files was a CPU amplifier bounded only by the
				// per-file timeout times the file count (#377). Six walkers shared the pattern;
				// the issue named one.
				_ = err
			}
		case "udta":
			err := parseUdtaBoxWithContext(ctx, boxData, metadata)
			if err != nil {
				// Non-fatal: this child is unreadable, the rest of the box is not. Deliberately
				// NOT `continue` — that skipped the `offset += int(size)` at the foot of the
				// loop, so the walk stopped advancing and spun until the 30s processing timeout
				// cancelled it. Measured: a 16-byte `[moov > mvhd(8, empty)]` burned 30s of CPU,
				// and a 24-byte `[moov > trak > tkhd(empty)]` did the same through the trak
				// walker — so a directory of tiny files was a CPU amplifier bounded only by the
				// per-file timeout times the file count (#377). Six walkers shared the pattern;
				// the issue named one.
				_ = err
			}
		case "trak":
			err := parseTrakBoxWithContext(ctx, boxData, metadata)
			if err != nil {
				// Non-fatal: this child is unreadable, the rest of the box is not. Deliberately
				// NOT `continue` — that skipped the `offset += int(size)` at the foot of the
				// loop, so the walk stopped advancing and spun until the 30s processing timeout
				// cancelled it. Measured: a 16-byte `[moov > mvhd(8, empty)]` burned 30s of CPU,
				// and a 24-byte `[moov > trak > tkhd(empty)]` did the same through the trak
				// walker — so a directory of tiny files was a CPU amplifier bounded only by the
				// per-file timeout times the file count (#377). Six walkers shared the pattern;
				// the issue named one.
				_ = err
			}
		case "meta":
			// A moov-level meta, which had no case here at all: parseMetaBoxWithContext was
			// reachable only from parseUdtaBoxWithContext, so `moov > meta` was never visited. That
			// is where Apple writes its keys/ilst pair — measured on a real macOS recording, see
			// apple-keys.go — so on those files the descriptive metadata was unreachable before any
			// question of decoding the index mapping arose.
			err := parseMetaBoxWithContext(ctx, boxData, metadata)
			if err != nil {
				// Non-fatal, and not `continue`, for the reason given on the arms above.
				_ = err
			}
		}

		offset += int(size)
	}

	return nil
}

// parseMvhdBox parses the movie header box
func parseMvhdBox(data []byte, metadata *VideoMetadata) error {
	if len(data) < 24 {
		return fmt.Errorf("mvhd box too small")
	}

	version := data[0]
	var timeScale, duration uint32
	var creationTime uint32

	if version == 0 {
		// 32-bit version
		if len(data) < 32 {
			return fmt.Errorf("mvhd v0 box too small")
		}
		creationTime = binary.BigEndian.Uint32(data[4:8])
		timeScale = binary.BigEndian.Uint32(data[12:16])
		duration = binary.BigEndian.Uint32(data[16:20])
	} else {
		// 64-bit version
		if len(data) < 44 {
			return fmt.Errorf("mvhd v1 box too small")
		}
		creationTime64 := binary.BigEndian.Uint64(data[4:12])
		// Safe conversion with bounds checking
		if creationTime64 > math.MaxUint32 {
			return fmt.Errorf("creation time value too large: %d", creationTime64)
		}
		creationTime = uint32(creationTime64)
		timeScale = binary.BigEndian.Uint32(data[20:24])
		duration64 := binary.BigEndian.Uint64(data[24:32])
		// Safe conversion with bounds checking
		if duration64 > math.MaxUint32 {
			return fmt.Errorf("duration value too large: %d", duration64)
		}
		duration = uint32(duration64)
	}

	// Calculate duration
	if timeScale > 0 {
		metadata.Duration = time.Duration(duration) * time.Second / time.Duration(timeScale)
	}

	// Convert creation time (seconds since 1904-01-01)
	if creationTime > 0 {
		// MP4 epoch is 1904-01-01, Unix epoch is 1970-01-01
		// Difference is 66 years = 2082844800 seconds
		const mp4Epoch = 2082844800
		if creationTime > mp4Epoch {
			unixTime := creationTime - mp4Epoch
			metadata.CreatedDate = time.Unix(int64(unixTime), 0)
		}
	}

	return nil
}

// itunesAtomPrefix is the byte QuickTime/iTunes atom types are prefixed with —
// "©nam", "©ART", "©xyz" and friends. On the wire it is this SINGLE byte inside a
// four-byte type, but the Go source literal "©" is its two-byte UTF-8 encoding
// (c2 a9), which makes `"©nam"` a FIVE-byte string. Comparing a four-byte wire
// type against it can never be true, so every such case arm was unreachable:
//
//	string([]byte{0xA9, 'n', 'a', 'm'}) == "©nam"  // false
//
// canonicalBoxType translates the wire form into the spelling the case arms use,
// so they compare equal without every literal in the file having to be written as
// an escape.
const itunesAtomPrefix = 0xA9

// canonicalBoxType returns the four-byte box type as the case arms below spell
// it: a leading 0xA9 becomes the "©" rune. Any other type is returned unchanged,
// so plain types ("meta", "data", "desc") are unaffected.
func canonicalBoxType(raw []byte) string {
	if len(raw) == 4 && raw[0] == itunesAtomPrefix {
		return "©" + string(raw[1:])
	}
	return string(raw)
}

// isFourCC reports whether raw is a well-formed four-byte box type. Callers use
// this instead of len() on a canonicalized type, whose "©" prefix is two bytes.
func isFourCC(raw []byte) bool {
	return len(raw) == 4
}

// parseUdtaBoxWithContext parses the user data box containing metadata with context
func parseUdtaBoxWithContext(ctx context.Context, data []byte, metadata *VideoMetadata) error {
	offset := 0

	for offset < len(data) {
		// Check context for cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if offset+BoxHeaderSize > len(data) {
			break
		}

		boxType, payloadStart, payloadEnd, ok := readChildHeader(data, offset)
		if !ok {
			break
		}
		// The WHOLE box, so the `offset += int(size)` at the foot of this loop still steps over a
		// 64-bit largesize header's extra eight bytes rather than landing inside the payload.
		size := payloadEnd - offset

		boxData := data[payloadStart:payloadEnd]

		// 3GPP asset boxes first: their payload layout differs from the QuickTime string boxes the
		// switch below parses, so routing one into parseStringBox reads its version and flags as a
		// text length. Claiming them here keeps the two layouts from being confused. Returns false
		// for every non-3GPP type, so the switch is reached unchanged for everything else.
		if apply3GPPAsset(boxType, boxData, metadata) {
			offset += int(size)
			continue
		}

		switch boxType {
		case "meta":
			err := parseMetaBoxWithContext(ctx, boxData, metadata)
			if err != nil {
				// Non-fatal: this child is unreadable, the rest of the box is not. Deliberately
				// NOT `continue` — that skipped the `offset += int(size)` at the foot of the
				// loop, so the walk stopped advancing and spun until the 30s processing timeout
				// cancelled it. Measured: a 16-byte `[moov > mvhd(8, empty)]` burned 30s of CPU,
				// and a 24-byte `[moov > trak > tkhd(empty)]` did the same through the trak
				// walker — so a directory of tiny files was a CPU amplifier bounded only by the
				// per-file timeout times the file count (#377). Six walkers shared the pattern;
				// the issue named one.
				_ = err
			}
		case "©nam":
			metadata.Title = parseStringBox(boxData)
		case "©ART":
			metadata.Author = parseStringBox(boxData)
		case "©day":
			dateStr := parseStringBox(boxData)
			if date, err := parseDate(dateStr); err == nil {
				metadata.CreatedDate = date
			}
		case "©xyz":
			parsePositionAtom(boxData, metadata)
		case "loci":
			parseLociBox(boxData, metadata)
		case "©cpy":
			metadata.Copyright = parseStringBox(boxData)
		case "©des":
			metadata.Description = parseStringBox(boxData)
		case "©mak":
			metadata.CameraMake = parseStringBox(boxData)
		case "©mod":
			metadata.CameraModel = parseStringBox(boxData)
		case "©swr":
			metadata.Software = parseStringBox(boxData)
		// QuickTime-specific metadata atoms
		case "©cmt":
			metadata.Description = parseStringBox(boxData)
		case "©wrt":
			metadata.Creator = parseStringBox(boxData)
		case "©prd":
			metadata.Properties["Producer"] = parseStringBox(boxData)
		case "©dir":
			metadata.Properties["Director"] = parseStringBox(boxData)
		case "©gen":
			metadata.Properties["Genre"] = parseStringBox(boxData)
		case "©alb":
			metadata.Properties["Album"] = parseStringBox(boxData)
		case "©grp":
			metadata.Properties["Grouping"] = parseStringBox(boxData)
		case "©lyr":
			metadata.Properties["Lyrics"] = parseStringBox(boxData)
		case "©req":
			metadata.Properties["Requirements"] = parseStringBox(boxData)
		case "©src":
			metadata.Properties["Source"] = parseStringBox(boxData)
		case "©fmt":
			metadata.Properties["Format"] = parseStringBox(boxData)
		case "©inf":
			metadata.Properties["Information"] = parseStringBox(boxData)
		case "©dis":
			metadata.Properties["Disclaimer"] = parseStringBox(boxData)
		case "©wrn":
			metadata.Properties["Warning"] = parseStringBox(boxData)
		case "©url":
			metadata.Properties["URL"] = parseStringBox(boxData)
		case "©ed1", "©ed2", "©ed3", "©ed4", "©ed5", "©ed6", "©ed7", "©ed8", "©ed9":
			// Edit dates. Index off the END, not a fixed offset: "©" is two bytes
			// in Go source, so boxType[3:] sliced into the middle of the type and
			// produced "d1" instead of "1" — harmless only while these arms were
			// unreachable.
			editNum := boxType[len(boxType)-1:]
			dateStr := parseStringBox(boxData)
			if date, err := parseDate(dateStr); err == nil {
				metadata.Properties["EditDate"+editNum] = date.Format("2006-01-02 15:04:05")
			}
		}

		offset += int(size)
	}

	return nil
}

// parseMetaBoxWithContext parses the metadata box containing iTunes-style tags with context
func parseMetaBoxWithContext(ctx context.Context, data []byte, metadata *VideoMetadata) error {
	if len(data) < 4 {
		return fmt.Errorf("meta box too small")
	}

	// Where the children start: 0 for QuickTime, 4 for an ISO 14496-12 FullBox. This was an
	// unconditional 4, which made a QuickTime meta read its first child's type as that child's size
	// and abandon the box — see the comment in apple-keys.go for the measurement.
	start := metaChildOffset(data)

	// keys is read in a first pass, because ilst items reference it by index and a writer is not
	// obliged to put keys first. Two passes over a handful of children costs nothing and removes an
	// ordering assumption that would fail silently.
	keys := findKeysTable(ctx, data, start)

	offset := start

	for offset < len(data) {
		// Check context for cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if offset+BoxHeaderSize > len(data) {
			break
		}

		boxType, payloadStart, payloadEnd, ok := readChildHeader(data, offset)
		if !ok {
			break
		}
		// The WHOLE box, so the `offset += int(size)` at the foot of this loop still steps over a
		// 64-bit largesize header's extra eight bytes rather than landing inside the payload.
		size := payloadEnd - offset

		boxData := data[payloadStart:payloadEnd]

		if boxType == "ilst" {
			err := parseIlstBoxWithContext(ctx, boxData, metadata, keys)
			if err != nil {
				// Non-fatal: this child is unreadable, the rest of the box is not. Deliberately
				// NOT `continue` — that skipped the `offset += int(size)` at the foot of the
				// loop, so the walk stopped advancing and spun until the 30s processing timeout
				// cancelled it. Measured: a 16-byte `[moov > mvhd(8, empty)]` burned 30s of CPU,
				// and a 24-byte `[moov > trak > tkhd(empty)]` did the same through the trak
				// walker — so a directory of tiny files was a CPU amplifier bounded only by the
				// per-file timeout times the file count (#377). Six walkers shared the pattern;
				// the issue named one.
				_ = err
			}
		}

		offset += int(size)
	}

	return nil
}

// findKeysTable walks a meta box's children for a keys table and decodes it.
//
// Separate from the main walk so the caller can do it before reading any ilst, and returns nil when
// there is no keys box — which is the ordinary iTunes-style case where item types are four-character
// codes and no index mapping is needed.
func findKeysTable(ctx context.Context, data []byte, start int) map[uint32]metaKeyEntry {
	offset := start
	for offset < len(data) {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		if offset+BoxHeaderSize > len(data) {
			return nil
		}
		boxType, payloadStart, payloadEnd, ok := readChildHeader(data, offset)
		if !ok {
			return nil
		}
		if boxType == "keys" {
			return parseKeysBox(data[payloadStart:payloadEnd])
		}
		offset = payloadEnd
	}
	return nil
}

// parseIlstBoxWithContext parses the iTunes-style metadata list with context.
//
// keys is the index -> name table from a sibling keys box, or nil when there is none. Apple numbers
// its ilst items instead of naming them, so without that table an item's type word is four bytes of
// binary and the value it carries cannot be attributed to a field.
func parseIlstBoxWithContext(ctx context.Context, data []byte, metadata *VideoMetadata, keys map[uint32]metaKeyEntry) error {
	offset := 0

	for offset < len(data) {
		// Check context for cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if offset+BoxHeaderSize > len(data) {
			break
		}

		boxType, payloadStart, payloadEnd, ok := readChildHeader(data, offset)
		if !ok {
			break
		}
		// The type word sits at offset+4 whichever header form is in use, so the raw bytes the index
		// lookup below needs are read directly rather than returned by readChildHeader.
		rawType := data[offset+4 : offset+8]
		size := payloadEnd - offset

		boxData := data[payloadStart:payloadEnd]

		// A keys-indexed item: the type word is the 1-based index of its key, not a code.
		//
		// This branch always consumes the item, and that is the point. The switch below ends in a
		// default arm gated on isFourCC, which is only a length test — an index type is four bytes
		// wide and passes it — so falling through stored the value under a key made of raw bytes.
		// Caught by the real-file test, which found a property literally named "\x00\x00\x00\x01"
		// holding the binary payload of com.apple.quicktime.pixeldensity.
		if !isPrintableBoxType(rawType) {
			index := binary.BigEndian.Uint32(rawType)
			// appleDataValue rather than parseItunesTag: it honours the data box's own type
			// indicator, so a binary payload is not stringified into the text the validators scan.
			value := appleDataValue(boxData)

			if entry, ok := keys[index]; ok && applyAppleKeyValue(entry, value, metadata) {
				offset += int(size)
				continue
			}

			// No keys table, or no such index in it. The value is still text worth scanning, so it
			// is kept under a readable synthetic key rather than dropped — dropping it is a
			// SUPPRESSOR and an unreported value cannot be redacted. What is NOT kept is the raw
			// type as a key.
			if value != "" {
				metadata.Properties[fmt.Sprintf("QuickTimeItem_%d", index)] = value
			}
			offset += int(size)
			continue
		}

		// Parse iTunes metadata tags
		value := parseItunesTag(boxData)
		if value != "" {
			switch boxType {
			case "©nam":
				metadata.Title = value
			case "©ART":
				metadata.Author = value
			case "©day":
				if date, err := parseDate(value); err == nil {
					metadata.CreatedDate = date
				}
			case "©cpy":
				metadata.Copyright = value
			case "©des", "desc":
				metadata.Description = value
			case "©mak":
				metadata.CameraMake = value
			case "©mod":
				metadata.CameraModel = value
			case "©swr":
				metadata.Software = value
			case "©xyz":
				parseGPSString(value, metadata)
			default:
				// Store unknown tags in properties. The length test is on the raw
				// four-byte wire type, not on boxType: a canonicalized "©too" is
				// five bytes in Go, and testing len(boxType) == 4 here would drop
				// every unrecognized iTunes tag instead of recording it.
				if isFourCC(data[offset+4 : offset+8]) {
					metadata.Properties[boxType] = value
				}
			}
		}

		offset += int(size)
	}

	return nil
}

// parseItunesTag parses an iTunes-style metadata tag
func parseItunesTag(data []byte) string {
	offset := 0

	for offset < len(data) {
		if offset+BoxHeaderSize > len(data) {
			break
		}

		boxType, payloadStart, payloadEnd, ok := readChildHeader(data, offset)
		if !ok {
			break
		}
		// The WHOLE box, so the `offset += int(size)` at the foot of this loop still steps over a
		// 64-bit largesize header's extra eight bytes rather than landing inside the payload.
		size := payloadEnd - offset

		boxData := data[payloadStart:payloadEnd]

		if boxType == "data" && len(boxData) >= 8 {
			// Skip type and locale (8 bytes)
			textData := boxData[8:]
			return strings.TrimSpace(string(textData))
		}

		offset += int(size)
	}

	return ""
}

// parseStringBox parses a QuickTime udta string box.
//
// These boxes are not raw text: the payload is a 2-byte big-endian text length
// followed by a 2-byte language code, then the characters. ffmpeg writes exactly
// this form, so returning the whole payload prefixed every extracted title,
// author and comment with four bytes of binary — e.g. "\x00\x0cU\xc4Jordan
// Ellis" rendered as " U<?>Jordan Ellis". That corrupts the text the validators
// then scan and the redactor must rewrite, and it is why the leading bytes showed
// up as replacement characters in reports.
//
// The header is only honored when it is self-consistent; some writers emit bare
// text, so an implausible declared length falls back to the raw payload rather
// than truncating real content.
func parseStringBox(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	const textHeaderSize = 4
	if len(data) >= textHeaderSize {
		textLen := int(binary.BigEndian.Uint16(data[0:2]))
		if textLen > 0 && textHeaderSize+textLen <= len(data) {
			return strings.TrimSpace(string(data[textHeaderSize : textHeaderSize+textLen]))
		}
	}

	return strings.TrimSpace(string(data))
}

// parsePositionAtom reads a ©xyz payload, which carries a position in EITHER of two encodings.
//
// The atom name does not say which, so the payload's SHAPE decides. ffmpeg writes a .mov ©xyz as a
// 2-byte text length, a 2-byte language code and then an ISO 6709 string; some cameras write three
// 16.16 fixed-point words instead. Reading the text form as fixed-point turns the length and
// language bytes into a latitude: the payload "\x00\x12\x55\xc4+36.3506-082.6985/" was reported as
// 18.335022, 11059.211639 at HIGH confidence, while the real position sat unreported in the same
// bytes (#399).
//
// The shape test is isobmff.FindISO6709, the same spec-derived pattern the redactor uses to locate a
// position. Sharing it is the point: the redactor's own notes record that these two readers
// disagreeing about what a position looks like is what produced the garbage value, and a second copy
// of the pattern here would let them drift apart again.
//
// A zero-filled payload still yields nothing, which is what keeps redaction verifiable by rescanning
// the output: it holds no ISO 6709 text, so it falls to the fixed-point branch, decodes to 0/0, and
// parseGPSBox drops that.
func parsePositionAtom(data []byte, metadata *VideoMetadata) {
	if match := isobmff.FindISO6709(data); match != nil {
		parseISO6709Location(string(match), metadata)
		return
	}
	parseGPSBox(data, metadata)
}

// parseLociBox reads a 3GPP/QuickTime loci atom, the form ffmpeg writes into .mp4 by default.
//
// Layout: a version byte and three flag bytes, a 2-byte language code, a NUL-terminated UTF-8 place
// name, a one-byte role, then LONGITUDE, LATITUDE and altitude as 16.16 fixed-point in that order —
// longitude first, unlike ©xyz — then a NUL-terminated astronomical body and NUL-terminated notes.
//
// The place name is location data in its own right and is kept. The reversed word order is the trap
// here: reading them as lat/lon swaps the coordinates, which stays plausible near the equator and is
// wrong everywhere else.
func parseLociBox(data []byte, metadata *VideoMetadata) {
	const (
		versionAndFlags = 4
		languageBytes   = 2
		roleBytes       = 1
		coordinateWords = 3 * 4
	)
	if len(data) < versionAndFlags+languageBytes+1+roleBytes+coordinateWords {
		return
	}

	offset := versionAndFlags + languageBytes
	nameEnd := bytes.IndexByte(data[offset:], 0)
	if nameEnd < 0 {
		return // unterminated name: the coordinate offsets below cannot be trusted
	}
	name := strings.TrimSpace(string(data[offset : offset+nameEnd]))
	offset += nameEnd + 1 + roleBytes

	if offset+coordinateWords > len(data) {
		return
	}
	// #nosec G115 -- bit-pattern preservation for sign-extension, as in parseGPSBox
	lon := float64(int32(binary.BigEndian.Uint32(data[offset:offset+4]))) / 65536.0
	// #nosec G115 -- see lon above
	lat := float64(int32(binary.BigEndian.Uint32(data[offset+4:offset+8]))) / 65536.0
	// #nosec G115 -- see lon above
	alt := float64(int32(binary.BigEndian.Uint32(data[offset+8:offset+12]))) / 65536.0

	if lat < -90 || lat > 90 || lon < -180 || lon > 180 {
		return // not a position on Earth; see parseISO6709Location on why this is dropped
	}
	if lat != 0 || lon != 0 {
		metadata.GPSLatitude = lat
		metadata.GPSLongitude = lon
		metadata.GPSAltitude = alt
	}
	if name != "" {
		metadata.Location = name
	}
}

// parseGPSBox parses GPS coordinates from binary data
func parseGPSBox(data []byte, metadata *VideoMetadata) {
	if len(data) < 12 {
		return
	}

	// GPS coordinates are stored as 32-bit fixed-point numbers
	// Read as uint32 first, then convert to int32 safely
	latUint := binary.BigEndian.Uint32(data[0:4])
	lonUint := binary.BigEndian.Uint32(data[4:8])
	altUint := binary.BigEndian.Uint32(data[8:12])

	// QuickTime/MP4 GPS atoms store coordinates as 32-bit signed fixed-point
	// values stored in big-endian uint32 fields. The conversion here is
	// intentional and reproduces the original bit pattern for sign-extension.
	// #nosec G115 -- bit-pattern preservation; not a magnitude conversion
	lat := int32(latUint)
	// #nosec G115 -- see lat above
	lon := int32(lonUint)
	// #nosec G115 -- see lat above
	alt := int32(altUint)

	// Convert fixed-point to float (divide by 65536)
	metadata.GPSLatitude = float64(lat) / 65536.0
	metadata.GPSLongitude = float64(lon) / 65536.0
	metadata.GPSAltitude = float64(alt) / 65536.0
}

// parseGPSString parses GPS coordinates from string format
func parseGPSString(gpsStr string, metadata *VideoMetadata) {
	gpsStr = strings.TrimSpace(gpsStr)

	// Handle DMS format (e.g., "36 deg 21' 2.16" N, 82 deg 41' 54.60" W, 447.403 m Above Sea Level")
	if strings.Contains(gpsStr, "deg") {
		parseDMSCoordinates(gpsStr, metadata)
		return
	}

	// Handle decimal degrees format (e.g., "36.350600, -82.698500, 447.403")
	parts := strings.Split(gpsStr, ",")
	if len(parts) >= 2 {
		if lat, err := strconv.ParseFloat(strings.TrimSpace(parts[0]), 64); err == nil {
			metadata.GPSLatitude = lat
		}
		if lon, err := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64); err == nil {
			metadata.GPSLongitude = lon
		}
		if len(parts) >= 3 {
			if alt, err := strconv.ParseFloat(strings.TrimSpace(parts[2]), 64); err == nil {
				metadata.GPSAltitude = alt
			}
		}
	}
}

// parseDate parses various date formats found in video metadata
func parseDate(dateStr string) (time.Time, error) {
	dateStr = strings.TrimSpace(dateStr)

	// Try common date formats
	formats := []string{
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05-07:00",
		// Apple writes com.apple.quicktime.creationdate with no colon in the zone offset —
		// "2025-06-16T19:12:48-0700" read off a real macOS recording. Without this layout the
		// value parsed as nothing and CreatedDate stayed zero.
		"2006-01-02T15:04:05-0700",
		"2006-01-02 15:04:05",
		"2006-01-02",
		"2006",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, dateStr); err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("unable to parse date: %s", dateStr)
}

// CanProcessVideo checks if the file can be processed as a video
func CanProcessVideo(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	return videoContainerExtensions[ext]
}

// parseTrakBoxWithContext parses track boxes to extract video technical details with context
func parseTrakBoxWithContext(ctx context.Context, data []byte, metadata *VideoMetadata) error {
	offset := 0

	for offset < len(data) {
		// Check context for cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if offset+BoxHeaderSize > len(data) {
			break
		}

		boxType, payloadStart, payloadEnd, ok := readChildHeader(data, offset)
		if !ok {
			break
		}
		// The WHOLE box, so the `offset += int(size)` at the foot of this loop still steps over a
		// 64-bit largesize header's extra eight bytes rather than landing inside the payload.
		size := payloadEnd - offset

		boxData := data[payloadStart:payloadEnd]

		switch boxType {
		case "tkhd":
			err := parseTkhdBox(boxData, metadata)
			if err != nil {
				// Non-fatal: this child is unreadable, the rest of the box is not. Deliberately
				// NOT `continue` — that skipped the `offset += int(size)` at the foot of the
				// loop, so the walk stopped advancing and spun until the 30s processing timeout
				// cancelled it. Measured: a 16-byte `[moov > mvhd(8, empty)]` burned 30s of CPU,
				// and a 24-byte `[moov > trak > tkhd(empty)]` did the same through the trak
				// walker — so a directory of tiny files was a CPU amplifier bounded only by the
				// per-file timeout times the file count (#377). Six walkers shared the pattern;
				// the issue named one.
				_ = err
			}
		case "mdia":
			err := parseMdiaBoxWithContext(ctx, boxData, metadata)
			if err != nil {
				// Non-fatal: this child is unreadable, the rest of the box is not. Deliberately
				// NOT `continue` — that skipped the `offset += int(size)` at the foot of the
				// loop, so the walk stopped advancing and spun until the 30s processing timeout
				// cancelled it. Measured: a 16-byte `[moov > mvhd(8, empty)]` burned 30s of CPU,
				// and a 24-byte `[moov > trak > tkhd(empty)]` did the same through the trak
				// walker — so a directory of tiny files was a CPU amplifier bounded only by the
				// per-file timeout times the file count (#377). Six walkers shared the pattern;
				// the issue named one.
				_ = err
			}
		case "udta":
			// A per-track user-data box. QuickTime allows udta at both movie and track level, and
			// only the movie level was read, so a ©cmt or ©des written per track was invisible to
			// the scan and therefore never redacted either. Real files carry it: a macOS system
			// recording on the host that reproduced this has `moov > trak > udta`.
			err := parseUdtaBoxWithContext(ctx, boxData, metadata)
			if err != nil {
				// Non-fatal, and not `continue`, for the reason given on the arms above.
				_ = err
			}
		case "meta":
			// The same reasoning as udta: a track-level meta carries the keys/ilst pair on some
			// writers, including the real recording quoted in apple-keys.go, whose first trak holds
			// its own meta > keys/ilst.
			err := parseMetaBoxWithContext(ctx, boxData, metadata)
			if err != nil {
				// Non-fatal, and not `continue`, for the reason given on the arms above.
				_ = err
			}
		}

		offset += int(size)
	}

	return nil
}

// parseTkhdBox parses track header box for video dimensions
func parseTkhdBox(data []byte, metadata *VideoMetadata) error {
	if len(data) < 32 {
		return fmt.Errorf("tkhd box too small")
	}

	version := data[0]
	var width, height uint32

	if version == 0 {
		// 32-bit version
		if len(data) < 84 {
			return fmt.Errorf("tkhd v0 box too small")
		}
		width = binary.BigEndian.Uint32(data[76:80]) >> 16  // Fixed-point 16.16
		height = binary.BigEndian.Uint32(data[80:84]) >> 16 // Fixed-point 16.16
	} else {
		// 64-bit version
		if len(data) < 96 {
			return fmt.Errorf("tkhd v1 box too small")
		}
		width = binary.BigEndian.Uint32(data[88:92]) >> 16  // Fixed-point 16.16
		height = binary.BigEndian.Uint32(data[92:96]) >> 16 // Fixed-point 16.16
	}

	// Only update if we haven't set dimensions yet and they're reasonable
	if metadata.Width == 0 && width > 0 && width < 10000 {
		metadata.Width = int(width)
	}
	if metadata.Height == 0 && height > 0 && height < 10000 {
		metadata.Height = int(height)
	}

	return nil
}

// parseMdiaBoxWithContext parses media box for codec information with context
func parseMdiaBoxWithContext(ctx context.Context, data []byte, metadata *VideoMetadata) error {
	offset := 0

	for offset < len(data) {
		// Check context for cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if offset+BoxHeaderSize > len(data) {
			break
		}

		boxType, payloadStart, payloadEnd, ok := readChildHeader(data, offset)
		if !ok {
			break
		}
		// The WHOLE box, so the `offset += int(size)` at the foot of this loop still steps over a
		// 64-bit largesize header's extra eight bytes rather than landing inside the payload.
		size := payloadEnd - offset

		boxData := data[payloadStart:payloadEnd]

		switch boxType {
		case "minf":
			err := parseMinfBoxWithContext(ctx, boxData, metadata)
			if err != nil {
				// Non-fatal: this child is unreadable, the rest of the box is not. Deliberately
				// NOT `continue` — that skipped the `offset += int(size)` at the foot of the
				// loop, so the walk stopped advancing and spun until the 30s processing timeout
				// cancelled it. Measured: a 16-byte `[moov > mvhd(8, empty)]` burned 30s of CPU,
				// and a 24-byte `[moov > trak > tkhd(empty)]` did the same through the trak
				// walker — so a directory of tiny files was a CPU amplifier bounded only by the
				// per-file timeout times the file count (#377). Six walkers shared the pattern;
				// the issue named one.
				_ = err
			}
		}

		offset += int(size)
	}

	return nil
}

// parseMinfBoxWithContext parses media information box with context
func parseMinfBoxWithContext(ctx context.Context, data []byte, metadata *VideoMetadata) error {
	offset := 0

	for offset < len(data) {
		// Check context for cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if offset+BoxHeaderSize > len(data) {
			break
		}

		boxType, payloadStart, payloadEnd, ok := readChildHeader(data, offset)
		if !ok {
			break
		}
		// The WHOLE box, so the `offset += int(size)` at the foot of this loop still steps over a
		// 64-bit largesize header's extra eight bytes rather than landing inside the payload.
		size := payloadEnd - offset

		boxData := data[payloadStart:payloadEnd]

		switch boxType {
		case "stbl":
			err := parseStblBoxWithContext(ctx, boxData, metadata)
			if err != nil {
				// Non-fatal: this child is unreadable, the rest of the box is not. Deliberately
				// NOT `continue` — that skipped the `offset += int(size)` at the foot of the
				// loop, so the walk stopped advancing and spun until the 30s processing timeout
				// cancelled it. Measured: a 16-byte `[moov > mvhd(8, empty)]` burned 30s of CPU,
				// and a 24-byte `[moov > trak > tkhd(empty)]` did the same through the trak
				// walker — so a directory of tiny files was a CPU amplifier bounded only by the
				// per-file timeout times the file count (#377). Six walkers shared the pattern;
				// the issue named one.
				_ = err
			}
		}

		offset += int(size)
	}

	return nil
}

// parseStblBoxWithContext parses sample table box for codec details with context
func parseStblBoxWithContext(ctx context.Context, data []byte, metadata *VideoMetadata) error {
	offset := 0

	for offset < len(data) {
		// Check context for cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if offset+BoxHeaderSize > len(data) {
			break
		}

		boxType, payloadStart, payloadEnd, ok := readChildHeader(data, offset)
		if !ok {
			break
		}
		// The WHOLE box, so the `offset += int(size)` at the foot of this loop still steps over a
		// 64-bit largesize header's extra eight bytes rather than landing inside the payload.
		size := payloadEnd - offset

		boxData := data[payloadStart:payloadEnd]

		switch boxType {
		case "stsd":
			err := parseStsdBox(boxData, metadata)
			if err != nil {
				// Non-fatal: this child is unreadable, the rest of the box is not. Deliberately
				// NOT `continue` — that skipped the `offset += int(size)` at the foot of the
				// loop, so the walk stopped advancing and spun until the 30s processing timeout
				// cancelled it. Measured: a 16-byte `[moov > mvhd(8, empty)]` burned 30s of CPU,
				// and a 24-byte `[moov > trak > tkhd(empty)]` did the same through the trak
				// walker — so a directory of tiny files was a CPU amplifier bounded only by the
				// per-file timeout times the file count (#377). Six walkers shared the pattern;
				// the issue named one.
				_ = err
			}
		}

		offset += int(size)
	}

	return nil
}

// parseStsdBox parses sample description box for codec information
func parseStsdBox(data []byte, metadata *VideoMetadata) error {
	if len(data) < 8 {
		return fmt.Errorf("stsd box too small")
	}

	// Skip version, flags, and entry count
	offset := 8

	if offset+BoxHeaderSize > len(data) {
		return fmt.Errorf("stsd entry too small")
	}

	// Read first sample description entry
	size := binary.BigEndian.Uint32(data[offset : offset+4])
	codecType := string(data[offset+4 : offset+8])

	if size < BoxHeaderSize || offset+int(size) > len(data) {
		return fmt.Errorf("invalid stsd entry size")
	}

	// Map codec types to readable names
	switch codecType {
	case "avc1", "avc3":
		metadata.Codec = "H.264/AVC"
	case "hev1", "hvc1":
		metadata.Codec = "H.265/HEVC"
	case "mp4v":
		metadata.Codec = "MPEG-4 Visual"
	case "jpeg":
		metadata.Codec = "Motion JPEG"
	case "png ":
		metadata.Codec = "PNG"
	default:
		if metadata.Codec == "" || metadata.Codec == "QuickTime" {
			metadata.Codec = codecType
		}
	}

	return nil
}

// ToProcessedContent converts VideoMetadata to ProcessedContent format
func (vm *VideoMetadata) ToProcessedContent() string {
	var content strings.Builder

	// File information (excluding file system details per requirements)
	if vm.MimeType != "" {
		content.WriteString(fmt.Sprintf("MimeType: %s\n", vm.MimeType))
	}

	// Video technical specifications
	if vm.Duration > 0 {
		content.WriteString(fmt.Sprintf("Duration: %s\n", vm.Duration.String()))
	}
	if vm.Width > 0 {
		content.WriteString(fmt.Sprintf("Width: %d\n", vm.Width))
	}
	if vm.Height > 0 {
		content.WriteString(fmt.Sprintf("Height: %d\n", vm.Height))
	}
	if vm.FrameRate > 0 {
		content.WriteString(fmt.Sprintf("FrameRate: %.2f\n", vm.FrameRate))
	}
	if vm.Codec != "" {
		content.WriteString(fmt.Sprintf("Codec: %s\n", vm.Codec))
	}

	// Metadata fields
	if vm.Title != "" {
		content.WriteString(fmt.Sprintf("Title: %s\n", vm.Title))
	}
	if vm.Description != "" {
		content.WriteString(fmt.Sprintf("Description: %s\n", vm.Description))
	}
	if vm.Author != "" {
		content.WriteString(fmt.Sprintf("Author: %s\n", vm.Author))
	}
	if vm.Creator != "" && vm.Creator != vm.Author {
		content.WriteString(fmt.Sprintf("Creator: %s\n", vm.Creator))
	}
	if vm.Copyright != "" {
		content.WriteString(fmt.Sprintf("Copyright: %s\n", vm.Copyright))
	}

	// Dates
	if !vm.CreatedDate.IsZero() {
		content.WriteString(fmt.Sprintf("CreationDate: %s\n", vm.CreatedDate.Format("2006:01:02 15:04:05-07:00")))
	}
	if !vm.ModifiedDate.IsZero() {
		content.WriteString(fmt.Sprintf("ModificationDate: %s\n", vm.ModifiedDate.Format("2006:01:02 15:04:05-07:00")))
	}

	// GPS and location data (high priority for privacy detection)
	// Consolidate GPS coordinates into a single field for consistency with image metadata
	if vm.GPSLatitude != 0 || vm.GPSLongitude != 0 {
		consolidatedGPS := fmt.Sprintf("%.6f, %.6f", vm.GPSLatitude, vm.GPSLongitude)
		if vm.GPSAltitude != 0 {
			consolidatedGPS = fmt.Sprintf("%s, %.2f", consolidatedGPS, vm.GPSAltitude)
		}
		content.WriteString(fmt.Sprintf("GPS_Coordinates: %s\n", consolidatedGPS))
	}
	if vm.Location != "" {
		content.WriteString(fmt.Sprintf("Location: %s\n", vm.Location))
	}

	// Device information (privacy-sensitive)
	if vm.CameraMake != "" {
		content.WriteString(fmt.Sprintf("CameraMake: %s\n", vm.CameraMake))
	}
	if vm.CameraModel != "" {
		content.WriteString(fmt.Sprintf("CameraModel: %s\n", vm.CameraModel))
	}
	if vm.Software != "" {
		content.WriteString(fmt.Sprintf("Software: %s\n", vm.Software))
	}

	// Additional properties, emitted in sorted key order. Ranging over the map
	// directly made the extracted text (and therefore finding line numbers and
	// the byte-for-byte redaction output) vary run to run — verified on a real
	// .mov. The image metadata path already sorts its keys for this reason.
	propKeys := make([]string, 0, len(vm.Properties))
	for key := range vm.Properties {
		propKeys = append(propKeys, key)
	}
	sort.Strings(propKeys)
	for _, key := range propKeys {
		if value := vm.Properties[key]; value != "" {
			content.WriteString(fmt.Sprintf("%s: %s\n", key, value))
		}
	}

	return content.String()
}

// GetSupportedVideoFormats returns the list of supported video formats
func GetSupportedVideoFormats() []string {
	formats := make([]string, 0, len(videoContainerExtensions))
	for ext := range videoContainerExtensions {
		formats = append(formats, ext)
	}
	sort.Strings(formats) // map order is random; a advertised-format list must be stable
	return formats
}

// OptimizedVideoReader provides optimized reading for video files
type OptimizedVideoReader struct {
	file       *os.File
	fileSize   int64
	position   int64
	bufferSize int
}

// NewOptimizedVideoReader creates a new optimized video reader
func NewOptimizedVideoReader(filePath string) (*OptimizedVideoReader, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}

	stat, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to get file stats: %w", err)
	}

	return &OptimizedVideoReader{
		file:       file,
		fileSize:   stat.Size(),
		position:   0,
		bufferSize: 64 * 1024, // 64KB buffer
	}, nil
}

// GetFileSize returns the file size
func (ovr *OptimizedVideoReader) GetFileSize() int64 {
	return ovr.fileSize
}

// Close closes the reader
func (ovr *OptimizedVideoReader) Close() error {
	return ovr.file.Close()
}

// readTopLevelHeaderAt reads one top-level box header at off and returns its type, its TOTAL size
// (header included) and the length of that header.
//
// Takes an io.ReaderAt rather than the file so a test can wrap it and count exactly how many bytes
// the walk reads — which is the only way to assert that a media payload is never touched.
//
// Every declared size is checked against the real end of the file before it is trusted. That check
// is written as `total > fileSize-off`, deliberately NOT as `off+total > fileSize`: a 64-bit
// largesize near 2^63 makes the addition overflow to a negative offset, which a bounds test phrased
// that way silently accepts. Both operands here are non-negative, so the comparison cannot wrap.
func readTopLevelHeaderAt(r io.ReaderAt, off, fileSize int64) (boxType string, total, hdrLen int64, err error) {
	var head [ExtendedBoxSize]byte
	if _, err = io.ReadFull(io.NewSectionReader(r, off, BoxHeaderSize), head[:BoxHeaderSize]); err != nil {
		return "", 0, 0, err
	}
	size32 := binary.BigEndian.Uint32(head[0:4])
	boxType = string(head[4:8])
	hdrLen = BoxHeaderSize

	switch size32 {
	case 1:
		// The real size is a 64-bit value following the type.
		if _, err = io.ReadFull(io.NewSectionReader(r, off+BoxHeaderSize, 8), head[BoxHeaderSize:ExtendedBoxSize]); err != nil {
			return "", 0, 0, err
		}
		hdrLen = ExtendedBoxSize
		size64 := binary.BigEndian.Uint64(head[BoxHeaderSize:ExtendedBoxSize])
		if size64 > math.MaxInt64 {
			return boxType, 0, hdrLen, fmt.Errorf("box %q declares an unrepresentable 64-bit size", boxType)
		}
		total = int64(size64)
	case 0:
		// Size 0 means "extends to the end of the file", permitted for the last box.
		total = fileSize - off
	default:
		total = int64(size32)
	}

	// A box cannot be smaller than its own header. Stepping by such a size would not advance the
	// walk, which is the spin this file has already been bitten by once.
	if total < hdrLen {
		return boxType, 0, hdrLen, fmt.Errorf("box %q declares %d bytes, smaller than its %d-byte header", boxType, total, hdrLen)
	}
	if total > fileSize-off {
		return boxType, 0, hdrLen, errDeclaredOverrun
	}
	return boxType, total, hdrLen, nil
}

// parseMP4ContainerOptimized walks the top-level boxes and parses the metadata ones.
//
// The walk is by ABSOLUTE OFFSET and has no positional budget, because moov is legal anywhere in the
// file. ISO/IEC 14496-12 cl. 8.2.1.1 says moov is "normally ... close to the beginning or end of the
// file, though this is not required", and Apple's QTFF is blunter: "QuickTime does not impose any
// rules about the order of these atoms." ffmpeg and every camera measured on this machine write moov
// LAST by default; faststart is a second pass nobody runs by accident.
//
// What was here before charged a 10MB budget for every box it stepped over, including the mdat it
// skipped with a bare seek and never read — so the counter measured a file offset, not bytes read,
// and a 12MB movie exhausted a "metadata" allowance while costing no memory at all. The walk then
// stopped with a bare `break` and returned nil, so a file whose entire moov was never reached was
// reported as a complete, clean scan at exit 0 (#398).
//
// Cost: TIME is O(number of top-level boxes) — a handful of 8-byte header reads. MEMORY is
// O(min(|moov|, MaxMoovParse)), independent of the file's size, because no other box is ever read.
// A media payload is stepped over by arithmetic, not even seeked.
//
// Always returns nil once the file is open. Lost coverage is reported through
// metadata.ExtractionWarning instead, so a file that yielded SOME metadata keeps it — an error here
// would throw away findings the walk had already collected.
func parseMP4ContainerOptimized(ctx context.Context, reader *OptimizedVideoReader, metadata *VideoMetadata) error {
	fileSize := reader.GetFileSize()
	cur := int64(0)
	boxes := 0
	sawMoov := false

	for cur+BoxHeaderSize <= fileSize {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if boxes >= MaxTopLevelBoxes {
			noteTruncation(metadata, fmt.Sprintf(
				"video metadata may be incomplete: the box walk stopped after %d top-level boxes",
				MaxTopLevelBoxes))
			break
		}
		boxes++

		boxType, total, hdrLen, err := readTopLevelHeaderAt(reader.file, cur, fileSize)
		switch {
		case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
			// A clean end of file, or a few stray bytes after the last box. Nothing was lost.
			return nil
		case errors.Is(err, errDeclaredOverrun):
			// A truncated file. Read to its real end rather than abandoning the box: a partial
			// moov still yields values, and the operator is told coverage was cut short.
			noteTruncation(metadata, fmt.Sprintf(
				"video metadata may be incomplete: the %q box at offset %d declares more bytes than "+
					"the file holds, so it was read only to the file's real end", boxType, cur))
			total = fileSize - cur
			if total < hdrLen {
				return nil
			}
		case err != nil:
			noteTruncation(metadata, fmt.Sprintf(
				"video metadata may be incomplete: the box structure could not be followed past "+
					"offset %d (%v)", cur, err))
			return nil
		}

		payloadStart := cur + hdrLen
		payloadLen := total - hdrLen

		switch boxType {
		case "moov":
			sawMoov = true
			readLen := payloadLen
			if readLen > MaxMoovParse {
				readLen = MaxMoovParse
				noteTruncation(metadata, fmt.Sprintf(
					"video metadata may be incomplete: the moov box is %d bytes and only the first "+
						"%d were parsed", payloadLen, MaxMoovParse))
			}
			data := make([]byte, readLen)
			if _, err := io.ReadFull(io.NewSectionReader(reader.file, payloadStart, readLen), data); err != nil {
				noteTruncation(metadata, fmt.Sprintf(
					"video metadata may be incomplete: the moov box at offset %d could not be read "+
						"in full (%v)", cur, err))
			} else if err := parseMoovBoxWithContext(ctx, data, metadata); err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				noteTruncation(metadata, fmt.Sprintf(
					"video metadata may be incomplete: the moov box at offset %d could not be "+
						"parsed in full (%v)", cur, err))
			}
		case "ftyp":
			// Only the brands are wanted, and they sit at the front of the payload.
			readLen := payloadLen
			if readLen > 1024 {
				readLen = 1024
			}
			data := make([]byte, readLen)
			if _, err := io.ReadFull(io.NewSectionReader(reader.file, payloadStart, readLen), data); err == nil {
				_ = parseFtypBox(data, metadata) // brands are advisory; a bad ftyp is not a failure
			}
		default:
			// mdat, free, skip, wide, uuid and anything unrecognised: stepped over by arithmetic.
			// No read, no allocation, not even a seek — which is what makes a 90MB movie cost the
			// same as a 90KB one.
		}

		if metadata.ExtractionWarning != "" && errors.Is(err, errDeclaredOverrun) {
			// The file ended early; there is nothing after this box to walk.
			return nil
		}
		cur += total // total >= hdrLen >= BoxHeaderSize, so the walk always advances
	}

	if !sawMoov {
		noteTruncation(metadata,
			"video metadata may be incomplete: no moov box was found in the file")
	}
	return nil
}

// Helper functions for enhanced metadata extraction

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// max returns the maximum of two integers
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// isValidUTF8Subset checks if data contains mostly valid UTF-8 text
func isValidUTF8Subset(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	// Sample first 1KB to check if it's mostly text
	sampleSize := min(len(data), 1024)
	sample := data[:sampleSize]

	validChars := 0
	for _, b := range sample {
		// Count printable ASCII and common UTF-8 chars
		if (b >= 32 && b <= 126) || b == 9 || b == 10 || b == 13 {
			validChars++
		}
	}

	// Require at least 30% valid text characters
	return float64(validChars)/float64(sampleSize) > 0.3
}

// searchAppleMetadataInData searches for Apple QuickTime metadata in text data
func searchAppleMetadataInData(data string, metadata *VideoMetadata) {
	// Apple QuickTime metadata keys to search for
	appleMetadataKeys := map[string]string{
		"com.apple.quicktime.location.ISO6709":          "GPS_Location",
		"com.apple.quicktime.creationdate":              "CreationDate_Apple",
		"com.apple.quicktime.make":                      "CameraMake_Apple",
		"com.apple.quicktime.model":                     "CameraModel_Apple",
		"com.apple.quicktime.software":                  "Software_Apple",
		"com.apple.quicktime.author":                    "Author_Apple",
		"com.apple.quicktime.description":               "Description_Apple",
		"com.apple.quicktime.title":                     "Title_Apple",
		"com.apple.quicktime.copyright":                 "Copyright_Apple",
		"com.apple.quicktime.comment":                   "Comment_Apple",
		"com.apple.quicktime.artist":                    "Artist_Apple",
		"com.apple.quicktime.location.name":             "LocationName_Apple",
		"com.apple.quicktime.location.body":             "LocationBody_Apple",
		"com.apple.quicktime.camera.identifier":         "CameraIdentifier_Apple",
		"com.apple.quicktime.live-photo.auto":           "LivePhotoAuto_Apple",
		"com.apple.quicktime.content.identifier":        "ContentIdentifier_Apple",
		"com.apple.quicktime.user.rating":               "UserRating_Apple",
		"com.apple.quicktime.encoding.tool":             "EncodingTool_Apple",
		"com.apple.quicktime.network.sharing":           "NetworkSharing_Apple",
		"com.apple.quicktime.cloud.identifier":          "CloudIdentifier_Apple",
		"com.apple.quicktime.accessibility.description": "AccessibilityDescription_Apple",
	}

	// Handle keywords separately with environment variable for sensitive data
	keywordsKey := os.Getenv("APPLE_KEYWORDS_KEY")
	if keywordsKey == "" {
		keywordsKey = "Keywords_Apple" // Default fallback
	}
	appleMetadataKeys["com.apple.quicktime.keywords"] = keywordsKey

	// Search for each metadata key
	for metadataKey, propertyName := range appleMetadataKeys {
		// Skip anything the keys/ilst table already answered properly.
		//
		// This scrape reads the bytes FOLLOWING a key name, and inside a keys table what follows a
		// key name is the next key's name — so on an Apple file it produced field names as values,
		// shifted by one entry (see apple-keys.go). Now that the table is decoded, its answer is
		// authoritative and this fallback must not append a contradicting one: emitting both left
		// the reader with `CameraMake: Apple` and `CameraMake_Apple: m.apple.quicktime.model` side
		// by side, and fed the garbage to the validators as well.
		//
		// Keyed on the property the table writes for the same key, so the two paths cannot disagree
		// about which key they are talking about.
		if metadata.decodedAppleKeys[metadataKey] {
			continue
		}
		if strings.Contains(data, metadataKey) {
			if idx := strings.Index(data, metadataKey); idx >= 0 {
				// Extract the metadata value
				value := extractAppleMetadataValue(data[idx:min(idx+300, len(data))], metadataKey)
				if value != "" && isValidMetadataValue(value) {
					// Handle special cases first
					switch propertyName {
					case "GPS_Location":
						parseISO6709Location(value, metadata)
						if metadata.GPSLatitude != 0 || metadata.GPSLongitude != 0 {
							metadata.Properties["GPS_SOURCE"] = "Apple QuickTime Location"
						}
						// Don't add GPS_Location to Properties to avoid duplication with GPS_Coordinates
						continue
					}

					// Add to properties for non-GPS cases
					metadata.Properties[propertyName] = value

					// Handle other special cases
					switch propertyName {
					case "CreationDate_Apple":
						if date, err := parseDate(value); err == nil && metadata.CreatedDate.IsZero() {
							metadata.CreatedDate = date
						}
					case "CameraMake_Apple":
						if metadata.CameraMake == "" {
							metadata.CameraMake = value
						}
					case "CameraModel_Apple":
						if metadata.CameraModel == "" {
							metadata.CameraModel = value
						}
					case "Software_Apple":
						if metadata.Software == "" {
							metadata.Software = value
						}
					}
				}
			}
		}
	}
}

// searchMetadataPatternsInData searches for various metadata patterns in text data
func searchMetadataPatternsInData(data string, metadata *VideoMetadata) {
	// Common metadata patterns to search for
	metadataPatterns := map[string]string{
		"EXIF":      "EXIF_Data",
		"XMP":       "XMP_Data",
		"IPTC":      "IPTC_Data",
		"Canon":     "Canon_Metadata",
		"Nikon":     "Nikon_Metadata",
		"Sony":      "Sony_Metadata",
		"iPhone":    "iPhone_Metadata",
		"Android":   "Android_Metadata",
		"QuickTime": "QuickTime_Metadata",
		"user":      "User_Reference",
		"location":  "Location_Reference",
	}

	// Search for each pattern
	for pattern, propertyName := range metadataPatterns {
		if strings.Contains(strings.ToLower(data), strings.ToLower(pattern)) {
			lowerData := strings.ToLower(data)
			if idx := strings.Index(lowerData, strings.ToLower(pattern)); idx >= 0 {
				// Extract context around the pattern
				start := max(0, idx-50)
				end := min(len(data), idx+len(pattern)+50)

				if start < len(data) && end <= len(data) && start < end {
					context := data[start:end]
					// Clean up the context (remove non-printable characters)
					cleanContext := ""
					for _, c := range context {
						if c >= 32 && c <= 126 { // Printable ASCII
							cleanContext += string(c)
						} else {
							cleanContext += " "
						}
					}
					metadata.Properties[propertyName] = strings.TrimSpace(cleanContext)
				}
			}
		}
	}
}

// extractAppleMetadataValue extracts the value for an Apple QuickTime metadata key
func extractAppleMetadataValue(searchArea, metadataKey string) string {
	// For GPS location, look for ISO 6709 pattern
	if strings.Contains(metadataKey, "location.ISO6709") {
		for i := 0; i < len(searchArea)-20; i++ {
			if (searchArea[i] == '+' || searchArea[i] == '-') && i+20 < len(searchArea) {
				// Extract potential GPS string
				gpsCandidate := ""
				for j := i; j < len(searchArea) && j < i+50; j++ {
					c := searchArea[j]
					if (c >= '0' && c <= '9') || c == '.' || c == '+' || c == '-' {
						gpsCandidate += string(c)
					} else if len(gpsCandidate) > 10 {
						break
					}
				}

				// Check if this looks like ISO 6709 format
				if len(gpsCandidate) > 15 &&
					strings.Count(gpsCandidate, "+")+strings.Count(gpsCandidate, "-") >= 2 {
					return gpsCandidate
				}
			}
		}
	}

	// For other metadata, look for printable text after the key
	keyIndex := strings.Index(searchArea, metadataKey)
	if keyIndex >= 0 {
		// Look for text data after the key
		startSearch := keyIndex + len(metadataKey) + 10
		if startSearch < len(searchArea) {
			// Find the start of printable text
			for i := startSearch; i < len(searchArea)-5; i++ {
				if searchArea[i] >= 32 && searchArea[i] <= 126 { // Printable ASCII
					// Extract the text value
					value := ""
					for j := i; j < len(searchArea) && j < i+200; j++ {
						c := searchArea[j]
						if c >= 32 && c <= 126 { // Printable ASCII
							value += string(c)
						} else if len(value) > 3 {
							break
						} else {
							value = "" // Reset if we hit non-printable too early
						}
					}

					// Clean up the value
					value = strings.TrimSpace(value)
					if len(value) > 3 && len(value) < 500 { // Reasonable length
						return value
					}
				}
			}
		}
	}

	return ""
}

// parseISO6709Location parses GPS coordinates in ISO 6709 Annex H format.
//
// The three forms differ only in how many INTEGER digits the angle carries, and that is the whole
// difficulty: ±DD, ±DDMM and ±DDMMSS for latitude, ±DDD, ±DDDMM and ±DDDMMSS for longitude, with an
// optional fraction on the smallest unit present. A plain ParseFloat is correct for the first form
// and silently wrong for the other two — measured before this change, "+4012.22-07500.25/" (40°12.22′
// north, 75°00.25′ west) reported latitude 4012.22 and longitude -7500.25, and
// "+401230.5-0750015.3/" reported 401230.5. An impossible coordinate at HIGH confidence is a false
// positive that also buries the real position, which is the pair of defects #399 is about.
//
// A value that cannot be a position on Earth is DROPPED rather than reported. That is what stops
// this function turning a misread payload into a finding, and it is why the caller may hand it a
// candidate it is not certain about.
func parseISO6709Location(iso6709Str string, metadata *VideoMetadata) {
	iso6709Str = strings.TrimSpace(iso6709Str)
	iso6709Str = strings.TrimSuffix(iso6709Str, "/")
	if iso6709Str == "" {
		return
	}

	// A CRS suffix is permitted after the height and is not part of any angle.
	if i := strings.Index(iso6709Str, "CRS"); i > 0 {
		iso6709Str = iso6709Str[:i]
	}

	// Split on the signs that introduce each component; every component keeps its own sign.
	var fields []string
	start := 0
	for i := 1; i < len(iso6709Str); i++ {
		if iso6709Str[i] == '+' || iso6709Str[i] == '-' {
			fields = append(fields, iso6709Str[start:i])
			start = i
		}
	}
	fields = append(fields, iso6709Str[start:])
	if len(fields) < 2 {
		return
	}

	lat, latOK := decodeISO6709Angle(fields[0], 2, 90)
	lon, lonOK := decodeISO6709Angle(fields[1], 3, 180)
	if !latOK || !lonOK {
		// Not a position. Reporting half of one, or a value out of range, is worse than
		// reporting nothing: it is a finding the operator cannot act on.
		return
	}
	metadata.GPSLatitude = lat
	metadata.GPSLongitude = lon

	// Height is plain signed decimal metres, not a sexagesimal angle.
	if len(fields) >= 3 {
		if alt, err := strconv.ParseFloat(fields[2], 64); err == nil {
			metadata.GPSAltitude = alt
		}
	}
}

// decodeISO6709Angle converts one signed ISO 6709 angle to decimal degrees.
//
// degreeDigits is 2 for a latitude and 3 for a longitude; the digits beyond that are minutes, then
// seconds, and any fraction belongs to the smallest unit present. limit is the largest magnitude
// the angle may have. Reports false for anything that is not one of the three legal widths or is
// out of range, so a caller can use it as the shape test as well as the parse.
func decodeISO6709Angle(field string, degreeDigits int, limit float64) (float64, bool) {
	if len(field) < 2 || (field[0] != '+' && field[0] != '-') {
		return 0, false
	}
	sign, body := 1.0, field[1:]
	if field[0] == '-' {
		sign = -1.0
	}

	intPart, frac := body, ""
	if dot := strings.IndexByte(body, '.'); dot >= 0 {
		intPart, frac = body[:dot], body[dot:]
		if len(frac) < 2 {
			return 0, false // a trailing '.' with no digits
		}
	}
	for i := 0; i < len(intPart); i++ {
		if intPart[i] < '0' || intPart[i] > '9' {
			return 0, false
		}
	}

	// Only DD / DDMM / DDMMSS widths exist, so the surplus over the degree field is 0, 2 or 4.
	surplus := len(intPart) - degreeDigits
	if surplus != 0 && surplus != 2 && surplus != 4 {
		return 0, false
	}

	parse := func(s string) (float64, bool) {
		v, err := strconv.ParseFloat(s, 64)
		return v, err == nil
	}

	var deg, minutes, seconds float64
	var ok bool
	switch surplus {
	case 0:
		if deg, ok = parse(intPart + frac); !ok {
			return 0, false
		}
	case 2:
		if deg, ok = parse(intPart[:degreeDigits]); !ok {
			return 0, false
		}
		if minutes, ok = parse(intPart[degreeDigits:] + frac); !ok {
			return 0, false
		}
	case 4:
		if deg, ok = parse(intPart[:degreeDigits]); !ok {
			return 0, false
		}
		if minutes, ok = parse(intPart[degreeDigits : degreeDigits+2]); !ok {
			return 0, false
		}
		if seconds, ok = parse(intPart[degreeDigits+2:] + frac); !ok {
			return 0, false
		}
	}
	if minutes >= 60 || seconds >= 60 {
		return 0, false
	}

	value := sign * (deg + minutes/60 + seconds/3600)
	if value < -limit || value > limit {
		return 0, false
	}
	return value, true
}

// parseDMSCoordinates parses GPS coordinates in degrees/minutes/seconds format
func parseDMSCoordinates(gpsStr string, metadata *VideoMetadata) {
	// Split by comma to get lat, lon, and altitude parts
	parts := strings.Split(gpsStr, ",")

	for i, part := range parts {
		part = strings.TrimSpace(part)

		if i == 0 || i == 1 {
			// Parse latitude or longitude. Only write on success: this function
			// is reached for ANY property value containing "deg"
			// (searchForGPSInMetadata), including free text like "Rotated 90 deg
			// in post", and it may run after the ©xyz atom has already supplied a
			// real coordinate. Unconditionally assigning the parse result let a
			// non-coordinate string overwrite a known-good latitude with 0, so a
			// video's true location was never reported at all.
			coord, ok := parseDMSCoordinate(part)
			if !ok {
				continue
			}
			if i == 0 {
				metadata.GPSLatitude = coord
			} else {
				metadata.GPSLongitude = coord
			}
		} else if i == 2 && strings.Contains(part, "m") {
			// Parse altitude (e.g., "447.403 m Above Sea Level")
			fields := strings.Fields(part)
			if len(fields) > 0 {
				if alt, err := strconv.ParseFloat(fields[0], 64); err == nil {
					metadata.GPSAltitude = alt
				}
			}
		}
	}
}

// dmsPattern matches one DMS coordinate anywhere in a string, so a prose prefix
// or trailing commentary cannot corrupt the numbers.
//
// The previous implementation split on "deg" and parsed everything to its left
// as the degrees. For the exiftool-style value "GPS Position: 36 deg 21' 2.16" N"
// that left ParseFloat("GPS Position: 36"), which errors; the error was
// discarded and degrees kept its zero value, so the function returned 0.350600
// for 36.350600 — the minutes/seconds remainder alone. Plausible-looking and
// silently ~2400 km wrong.
//
// Groups: 1=sign 2=degrees 3=minutes 4=seconds 5=hemisphere. Minutes and
// seconds are optional so "36 deg" and "36 deg 21'" still parse. The hemisphere
// letter needs no preceding space (the old suffix test required " N", so
// `82 deg 41' 54.60"W` lost its sign AND its seconds, landing at +82.68 —
// the wrong hemisphere entirely).
var dmsPattern = regexp.MustCompile(`(?i)(-?)\s*(\d+(?:\.\d+)?)\s*deg(?:rees)?\s*(?:(\d+(?:\.\d+)?)\s*'\s*(?:(\d+(?:\.\d+)?)\s*")?)?\s*([NSEW])?`)

// Bounds of the slice searched around the "deg" literal. A DMS coordinate is
// short: the longest realistic form, `-180 deg 59' 59.9999" W`, fits well inside
// these margins.
const (
	dmsWindowBefore = 24
	dmsWindowAfter  = 48
)

// dmsSearchWindow narrows the input to a bounded slice around the first "deg"
// before the regex runs.
//
// Both dmsPattern groups that could start a match — the optional sign and the
// leading \s* — can match empty, so RE2 has no required first byte to prefilter
// on and its submatch engine walks every offset in the input. On a 32 KB
// property value that measured 1.17 ms per call, versus 5 µs for the string-split
// this replaced: a 230x regression on a path fed by free text from the file
// (searchForGPSInMetadata hands over ANY property value containing "deg", and
// property values are attacker-influenced). Locating the literal first with the
// hardware-accelerated strings.Index and matching only the surrounding window
// brings the same 32 KB case to 1.4 µs — faster than the code it replaces, with
// identical results, because a coordinate cannot span more than these margins.
//
// The locate is case-sensitive to match the caller's own gate
// (strings.Contains(value, "deg") in searchForGPSInMetadata and parseGPSString);
// a value whose only "deg" were uppercase never reaches this function at all.
func dmsSearchWindow(s string) string {
	s = strings.TrimSpace(s)

	idx := strings.Index(s, "deg")
	if idx < 0 {
		// No "deg" at all: nothing for dmsPattern to match, and returning the
		// full string would put us back on the slow all-offsets scan.
		return ""
	}

	lo := idx - dmsWindowBefore
	if lo < 0 {
		lo = 0
	}
	hi := idx + dmsWindowAfter
	if hi > len(s) {
		hi = len(s)
	}
	return s[lo:hi]
}

// parseDMSCoordinate parses a single coordinate in DMS format, e.g.
// `36 deg 21' 2.16" N` or `82 deg 41' 54.60" W`. It returns ok=false when the
// string contains no DMS coordinate at all, so callers can leave an existing
// value untouched rather than overwriting it with a meaningless zero.
func parseDMSCoordinate(coordStr string) (float64, bool) {
	m := dmsPattern.FindStringSubmatch(dmsSearchWindow(coordStr))
	if m == nil {
		return 0, false
	}

	// A bare "<number> deg" is not a coordinate. This function is reached for any
	// property value containing "deg", and free text like "Rotated 90 deg in post"
	// or "Field of view: 120 deg" would otherwise parse to a confident 90 or 120
	// and overwrite the real coordinate from the ©xyz atom. Require the minutes
	// field or a hemisphere letter — every DMS coordinate a camera writes has at
	// least one, and rotation/FOV values have neither.
	if m[3] == "" && m[5] == "" {
		return 0, false
	}

	degrees, err := strconv.ParseFloat(m[2], 64)
	if err != nil {
		return 0, false
	}

	// Minutes and seconds are optional; a missing group is the empty string and
	// contributes nothing.
	var minutes, seconds float64
	if m[3] != "" {
		if v, err := strconv.ParseFloat(m[3], 64); err == nil {
			minutes = v
		}
	}
	if m[4] != "" {
		if v, err := strconv.ParseFloat(m[4], 64); err == nil {
			seconds = v
		}
	}

	result := degrees + minutes/60.0 + seconds/3600.0

	// A leading "-" and a S/W hemisphere letter are two spellings of the same
	// sign, never two signs to compose. Negating the magnitude AFTER summing the
	// parts also fixes the old code's arithmetic: it parsed "-36" as the degrees
	// and then ADDED the positive minutes and seconds, yielding -35.649400 for
	// -36.350600.
	if m[1] == "-" || strings.EqualFold(m[5], "S") || strings.EqualFold(m[5], "W") {
		result = -result
	}

	return result, true
}

// isValidMetadataValue checks if a metadata value is valid and not corrupted
func isValidMetadataValue(value string) bool {
	// Reject empty or very short values
	if len(value) < 2 {
		return false
	}

	// Reject values that are mostly non-printable characters
	printableCount := 0
	for _, c := range value {
		if c >= 32 && c <= 126 {
			printableCount++
		}
	}

	// Require at least 70% printable characters
	if float64(printableCount)/float64(len(value)) < 0.7 {
		return false
	}

	// Reject values that look like corrupted data
	corruptedPatterns := []string{
		"*data", "*", "\\x", "\x00", "\xff", "????", "NULL", "null",
	}

	lowerValue := strings.ToLower(value)
	for _, pattern := range corruptedPatterns {
		if strings.Contains(lowerValue, pattern) {
			return false
		}
	}

	// Reject values that are just repeated characters
	if len(value) > 3 {
		firstChar := rune(value[0])
		allSame := true
		for _, c := range value {
			if c != firstChar {
				allSame = false
				break
			}
		}
		if allSame {
			return false
		}
	}

	return true
}

// Remove the unnecessary safeUint32ToSignedInt64 function as uint32 to int64 conversion is always safe
