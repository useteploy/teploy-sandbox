package run

import (
	"crypto/rand"
	"time"
)

// crockford base32, per the ULID spec.
const ulidAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// NewULID returns a 26-character ULID: 48-bit millisecond timestamp +
// 80 random bits. Run IDs are ULIDs so nothing in the API assumes a
// single box (the Tier-2 design constraint).
func NewULID(now time.Time) string {
	var bin [16]byte
	ms := uint64(now.UnixMilli())
	bin[0] = byte(ms >> 40)
	bin[1] = byte(ms >> 32)
	bin[2] = byte(ms >> 24)
	bin[3] = byte(ms >> 16)
	bin[4] = byte(ms >> 8)
	bin[5] = byte(ms)
	if _, err := rand.Read(bin[6:]); err != nil {
		panic(err) // crypto/rand failure is unrecoverable
	}

	// 16 bytes = 128 bits -> 26 base32 chars (130 bits, top 2 padded).
	var out [26]byte
	var acc uint64
	bits := 0
	pos := 25
	for i := 15; i >= 0; i-- {
		acc |= uint64(bin[i]) << bits
		bits += 8
		for bits >= 5 && pos >= 0 {
			out[pos] = ulidAlphabet[acc&31]
			acc >>= 5
			bits -= 5
			pos--
		}
	}
	for pos >= 0 {
		out[pos] = ulidAlphabet[acc&31]
		acc >>= 5
		pos--
	}
	return string(out[:])
}
