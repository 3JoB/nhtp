// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package http

import (
	"bytes"
	"encoding/binary"

	"github.com/3JoB/unsafeConvert"
)

// The algorithm uses at most sniffLen bytes to make its decision.
const sniffLen = 512

// DetectContentType implements the algorithm described
// at https://mimesniff.spec.whatwg.org/ to determine the
// Content-Type of the given data. It considers at most the
// first 512 bytes of data. DetectContentType always returns
// a valid MIME type: if it cannot determine a more specific one, it
// returns "application/octet-stream".
func DetectContentType(data []byte) string {
	if len(data) > sniffLen {
		data = data[:sniffLen]
	}

	// Index of the first non-whitespace byte in data.
	firstNonWS := 0
	for ; firstNonWS < len(data) && isWS(data[firstNonWS]); firstNonWS++ {
	}

	for _, sig := range sniffSignatures {
		if ct := sig.match(data, firstNonWS); ct != "" {
			return ct
		}
	}

	return "application/octet-stream" // fallback
}

// isWS reports whether the provided byte is a whitespace byte (0xWS)
// as defined in https://mimesniff.spec.whatwg.org/#terminology.
func isWS(b byte) bool {
	switch b {
	case '\t', '\n', '\x0c', '\r', ' ':
		return true
	}
	return false
}

// isTT reports whether the provided byte is a tag-terminating byte (0xTT)
// as defined in https://mimesniff.spec.whatwg.org/#terminology.
func isTT(b byte) bool {
	switch b {
	case ' ', '>':
		return true
	}
	return false
}

type sniffSig interface {
	// match returns the MIME type of the data, or "" if unknown.
	match(data []byte, firstNonWS int) string
}

// Data matching the table in section 6.
var sniffSignatures = []sniffSig{
	htmlSig("<!DOCTYPE HTML"),
	htmlSig("<HTML"),
	htmlSig("<HEAD"),
	htmlSig("<SCRIPT"),
	htmlSig("<IFRAME"),
	htmlSig("<H1"),
	htmlSig("<DIV"),
	htmlSig("<FONT"),
	htmlSig("<TABLE"),
	htmlSig("<A"),
	htmlSig("<STYLE"),
	htmlSig("<TITLE"),
	htmlSig("<B"),
	htmlSig("<BODY"),
	htmlSig("<BR"),
	htmlSig("<P"),
	htmlSig("<!--"),
	&maskedSig{
		mask:   unsafeConvert.BytesReflect("\xFF\xFF\xFF\xFF\xFF"),
		pat:    unsafeConvert.BytesReflect("<?xml"),
		skipWS: true,
		ct:     "text/xml; charset=utf-8"},
	&exactSig{sig: unsafeConvert.BytesReflect("%PDF-"), ct: "application/pdf"},
	&exactSig{sig: unsafeConvert.BytesReflect("%!PS-Adobe-"), ct: "application/postscript"},

	// UTF BOMs.
	&maskedSig{
		mask: unsafeConvert.BytesReflect("\xFF\xFF\x00\x00"),
		pat:  unsafeConvert.BytesReflect("\xFE\xFF\x00\x00"),
		ct:   "text/plain; charset=utf-16be",
	},
	&maskedSig{
		mask: unsafeConvert.BytesReflect("\xFF\xFF\x00\x00"),
		pat:  unsafeConvert.BytesReflect("\xFF\xFE\x00\x00"),
		ct:   "text/plain; charset=utf-16le",
	},
	&maskedSig{
		mask: unsafeConvert.BytesReflect("\xFF\xFF\xFF\x00"),
		pat:  unsafeConvert.BytesReflect("\xEF\xBB\xBF\x00"),
		ct:   "text/plain; charset=utf-8",
	},

	// Image types
	// For posterity, we originally returned "image/vnd.microsoft.icon" from
	// https://tools.ietf.org/html/draft-ietf-websec-mime-sniff-03#section-7
	// https://codereview.appspot.com/4746042
	// but that has since been replaced with "image/x-icon" in Section 6.2
	// of https://mimesniff.spec.whatwg.org/#matching-an-image-type-pattern
	&exactSig{sig: unsafeConvert.BytesReflect("\x00\x00\x01\x00"), ct: "image/x-icon"},
	&exactSig{sig: unsafeConvert.BytesReflect("\x00\x00\x02\x00"), ct: "image/x-icon"},
	&exactSig{sig: unsafeConvert.BytesReflect("BM"), ct: "image/bmp"},
	&exactSig{sig: unsafeConvert.BytesReflect("GIF87a"), ct: "image/gif"},
	&exactSig{sig: unsafeConvert.BytesReflect("GIF89a"), ct: "image/gif"},
	&maskedSig{
		mask: unsafeConvert.BytesReflect("\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF"),
		pat:  unsafeConvert.BytesReflect("RIFF\x00\x00\x00\x00WEBPVP"),
		ct:   "image/webp",
	},
	&exactSig{sig: unsafeConvert.BytesReflect("\x89PNG\x0D\x0A\x1A\x0A"), ct: "image/png"},
	&exactSig{sig: unsafeConvert.BytesReflect("\xFF\xD8\xFF"), ct: "image/jpeg"},

	// Audio and Video types
	// Enforce the pattern match ordering as prescribed in
	// https://mimesniff.spec.whatwg.org/#matching-an-audio-or-video-type-pattern
	&maskedSig{
		mask: unsafeConvert.BytesReflect("\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF"),
		pat:  unsafeConvert.BytesReflect("FORM\x00\x00\x00\x00AIFF"),
		ct:   "audio/aiff",
	},
	&maskedSig{
		mask: unsafeConvert.BytesReflect("\xFF\xFF\xFF"),
		pat:  unsafeConvert.BytesReflect("ID3"),
		ct:   "audio/mpeg",
	},
	&maskedSig{
		mask: unsafeConvert.BytesReflect("\xFF\xFF\xFF\xFF\xFF"),
		pat:  unsafeConvert.BytesReflect("OggS\x00"),
		ct:   "application/ogg",
	},
	&maskedSig{
		mask: unsafeConvert.BytesReflect("\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"),
		pat:  unsafeConvert.BytesReflect("MThd\x00\x00\x00\x06"),
		ct:   "audio/midi",
	},
	&maskedSig{
		mask: unsafeConvert.BytesReflect("\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF"),
		pat:  unsafeConvert.BytesReflect("RIFF\x00\x00\x00\x00AVI "),
		ct:   "video/avi",
	},
	&maskedSig{
		mask: unsafeConvert.BytesReflect("\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF"),
		pat:  unsafeConvert.BytesReflect("RIFF\x00\x00\x00\x00WAVE"),
		ct:   "audio/wave",
	},
	// 6.2.0.2. video/mp4
	mp4Sig{},
	// 6.2.0.3. video/webm
	&exactSig{sig: unsafeConvert.BytesReflect("\x1A\x45\xDF\xA3"), ct: "video/webm"},

	// Font types
	&maskedSig{
		// 34 NULL bytes followed by the string "LP"
		pat: unsafeConvert.BytesReflect("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00LP"),
		// 34 NULL bytes followed by \xF\xF
		mask: unsafeConvert.BytesReflect("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF"),
		ct:   "application/vnd.ms-fontobject",
	},
	&exactSig{sig: unsafeConvert.BytesReflect("\x00\x01\x00\x00"), ct: "font/ttf"},
	&exactSig{sig: unsafeConvert.BytesReflect("OTTO"), ct: "font/otf"},
	&exactSig{sig: unsafeConvert.BytesReflect("ttcf"), ct: "font/collection"},
	&exactSig{sig: unsafeConvert.BytesReflect("wOFF"), ct: "font/woff"},
	&exactSig{sig: unsafeConvert.BytesReflect("wOF2"), ct: "font/woff2"},

	// Archive types
	&exactSig{sig: unsafeConvert.BytesReflect("\x1F\x8B\x08"), ct: "application/x-gzip"},
	&exactSig{sig: unsafeConvert.BytesReflect("\x2B\x49\x6E\x73\x6E\x6F\x77\x7A\x69\x6C\x6C\x61\x20\x42\x72\x6F\x74\x6C\x69\x20\x43\x6F\x6D\x70\x72\x65\x73\x73\x6F\x72\x20\x20\x20\x43\x6F\x70\x79\x72\x69\x67\x68\x74\x20\x32\x30\x31\x34\x2D\x32\x30\x31\x39\x0A\x31\x0A"), ct: "application/brotli"},
	&exactSig{sig: unsafeConvert.BytesReflect("\x28\xB5\x2F\xFD"), ct: "application/zstd"},
	&exactSig{sig: unsafeConvert.BytesReflect("PK\x03\x04"), ct: "application/zip"},
	// RAR's signatures are incorrectly defined by the MIME spec as per
	//    https://github.com/whatwg/mimesniff/issues/63
	// However, RAR Labs correctly defines it at:
	//    https://www.rarlab.com/technote.htm#rarsign
	// so we use the definition from RAR Labs.
	// TODO: do whatever the spec ends up doing.
	&exactSig{sig: unsafeConvert.BytesReflect("Rar!\x1A\x07\x00"), ct: "application/x-rar-compressed"},     // RAR v1.5-v4.0
	&exactSig{sig: unsafeConvert.BytesReflect("Rar!\x1A\x07\x01\x00"), ct: "application/x-rar-compressed"}, // RAR v5+

	&exactSig{sig: unsafeConvert.BytesReflect("\x00\x61\x73\x6D"), ct: "application/wasm"},

	textSig{}, // should be last
}

type exactSig struct {
	sig []byte
	ct  string
}

func (e *exactSig) match(data []byte, firstNonWS int) string {
	if bytes.HasPrefix(data, e.sig) {
		return e.ct
	}
	return ""
}

type maskedSig struct {
	mask, pat []byte
	skipWS    bool
	ct        string
}

func (m *maskedSig) match(data []byte, firstNonWS int) string {
	// pattern matching algorithm section 6
	// https://mimesniff.spec.whatwg.org/#pattern-matching-algorithm

	if m.skipWS {
		data = data[firstNonWS:]
	}
	if len(m.pat) != len(m.mask) {
		return ""
	}
	if len(data) < len(m.pat) {
		return ""
	}
	for i, pb := range m.pat {
		maskedData := data[i] & m.mask[i]
		if maskedData != pb {
			return ""
		}
	}
	return m.ct
}

type htmlSig []byte

func (h htmlSig) match(data []byte, firstNonWS int) string {
	data = data[firstNonWS:]
	if len(data) < len(h)+1 {
		return ""
	}
	for i, b := range h {
		db := data[i]
		if b >= 'A' && b <= 'Z' {
			db &= 0xDF
		}
		if b != db {
			return ""
		}
	}
	// Next byte must be a tag-terminating byte(0xTT).
	if !isTT(data[len(h)]) {
		return ""
	}
	return "text/html; charset=utf-8"
}

var mp4ftype = unsafeConvert.BytesReflect("ftyp")
var mp4 = unsafeConvert.BytesReflect("mp4")

type mp4Sig struct{}

func (mp4Sig) match(data []byte, firstNonWS int) string {
	// https://mimesniff.spec.whatwg.org/#signature-for-mp4
	// c.f. section 6.2.1
	if len(data) < 12 {
		return ""
	}
	boxSize := int(binary.BigEndian.Uint32(data[:4]))
	if len(data) < boxSize || boxSize%4 != 0 {
		return ""
	}
	if !bytes.Equal(data[4:8], mp4ftype) {
		return ""
	}
	for st := 8; st < boxSize; st += 4 {
		if st == 12 {
			// Ignores the four bytes that correspond to the version number of the "major brand".
			continue
		}
		if bytes.Equal(data[st:st+3], mp4) {
			return "video/mp4"
		}
	}
	return ""
}

type textSig struct{}

func (textSig) match(data []byte, firstNonWS int) string {
	// c.f. section 5, step 4.
	for _, b := range data[firstNonWS:] {
		switch {
		case b <= 0x08,
			b == 0x0B,
			b >= 0x0E && b <= 0x1A,
			b >= 0x1C && b <= 0x1F:
			return ""
		}
	}
	return "text/plain; charset=utf-8"
}
