// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package audiolib

import (
	"io"
	"os"
)

// readDeclaredPayload reads a box or block payload whose length the FILE declared.
//
// Every length in these container formats is a value read out of the file, so it is
// attacker-controlled, and bounding one declaration by another bounds nothing. The FILE's own
// length is the only quantity here an attacker does not write, so the allocation is clamped to the
// bytes actually remaining from the current offset. On a well-formed file the declared length
// already fits and the clamp changes nothing.
//
// Measured before this existed (#457): a 52-byte .m4a whose mvhd declared 0xFFFFFFFF allocated
// 4096MB, and an 8-byte .flac whose first metadata block declared 0xFFFFFF allocated 16MB. Six of
// the .m4a form in one directory drove 3.90GB of resident memory from 220KB of input.
//
// Why resident memory and not just address space: Go does not zero a span it takes fresh from the
// OS, so a single bomb scanned by itself reserves 4GB that is never written and peak RSS stays near
// 30MB. Reuse a dirty span and the runtime must zero it, which faults every page in. That is why
// the single-file measurement looks harmless and the directory measurement does not, and why a
// reproducer for this class has to scan more than one file.
//
// The returned slice holds ONLY the bytes actually read, which is deliberately not the same length
// as the declaration. Callers must bound field access by len(payload). Sizing the buffer to the
// declaration and reading short left the tail zeroed, and those zeros parsed as real values — an
// mvhd claiming more than the file holds produced a timestamp and duration out of bytes that were
// never in the file.
func readDeclaredPayload(file *os.File, declared uint32) ([]byte, error) {
	n := int64(declared)

	// A failure to Stat or Seek leaves n at the declared value rather than refusing: these are
	// the same syscalls the surrounding parse already depends on, and a reader that cannot
	// report its own position is not a case this clamp can improve.
	if info, err := file.Stat(); err == nil {
		if pos, perr := file.Seek(0, io.SeekCurrent); perr == nil {
			if remaining := info.Size() - pos; remaining < n {
				n = remaining
			}
		}
	}
	if n <= 0 {
		return nil, nil
	}

	buf := make([]byte, n)
	read, err := io.ReadFull(file, buf)
	// A short read is expected when the declaration outran the file, and it is not an error
	// here: the caller's length checks are what decide whether the bytes present are enough.
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, err
	}
	return buf[:read], nil
}
