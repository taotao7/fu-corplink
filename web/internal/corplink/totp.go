package corplink

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"time"
)

const (
	totpDigits   = 6
	totpTimeStep = 30
)

// hotp computes an RFC 4226 HOTP value (HMAC-SHA1, dynamic truncation).
func hotp(key []byte, counter uint64, digits uint32) uint32 {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff

	mod := uint32(1)
	for i := uint32(0); i < digits; i++ {
		mod *= 10
	}
	return value % mod
}

// totpSlot is a generated code plus the seconds remaining in its time window.
type totpSlot struct {
	code     uint32
	secsLeft uint32
}

// totpOffset generates the TOTP code for the current 30s window shifted by
// slotOffset windows (used to correct for client/server clock skew derived from
// the server Date header).
func totpOffset(key []byte, slotOffset int) totpSlot {
	now := uint64(time.Now().Unix())
	slot := int64(now/totpTimeStep) + int64(slotOffset)
	return totpSlot{
		code:     hotp(key, uint64(slot), totpDigits),
		secsLeft: uint32(totpTimeStep - now%totpTimeStep),
	}
}
