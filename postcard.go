package secretbunker

// Minimal postcard (https://postcard.jamesmunns.com/wire-format) codec for
// the secret-bunker wire types. Only the shapes the protocol uses are
// implemented: unsigned LEB128 varints, raw u8, bool, length-prefixed
// strings and byte arrays, and sequences (varint count + elements). Enum
// variants are a varint discriminant followed by the fields in order.

import (
	"errors"
	"fmt"
	"unicode/utf8"
)

var errTruncated = errors.New("postcard: truncated input")

type encoder struct {
	buf []byte
}

func (e *encoder) uvarint(v uint64) {
	for v >= 0x80 {
		e.buf = append(e.buf, byte(v)|0x80)
		v >>= 7
	}
	e.buf = append(e.buf, byte(v))
}

func (e *encoder) u8(b byte) {
	e.buf = append(e.buf, b)
}

func (e *encoder) boolean(b bool) {
	if b {
		e.buf = append(e.buf, 1)
	} else {
		e.buf = append(e.buf, 0)
	}
}

func (e *encoder) bytes(b []byte) {
	e.uvarint(uint64(len(b)))
	e.buf = append(e.buf, b...)
}

func (e *encoder) str(s string) {
	e.bytes([]byte(s))
}

type decoder struct {
	buf []byte
	off int
}

func (d *decoder) uvarint() (uint64, error) {
	var v uint64
	var shift uint
	for {
		if d.off >= len(d.buf) {
			return 0, errTruncated
		}
		b := d.buf[d.off]
		d.off++
		if shift == 63 && b > 1 {
			return 0, errors.New("postcard: varint overflows u64")
		}
		v |= uint64(b&0x7f) << shift
		if b < 0x80 {
			return v, nil
		}
		shift += 7
	}
}

func (d *decoder) u8() (byte, error) {
	if d.off >= len(d.buf) {
		return 0, errTruncated
	}
	b := d.buf[d.off]
	d.off++
	return b, nil
}

func (d *decoder) boolean() (bool, error) {
	b, err := d.u8()
	if err != nil {
		return false, err
	}
	switch b {
	case 0:
		return false, nil
	case 1:
		return true, nil
	default:
		return false, fmt.Errorf("postcard: invalid bool byte %#x", b)
	}
}

func (d *decoder) bytes() ([]byte, error) {
	n, err := d.uvarint()
	if err != nil {
		return nil, err
	}
	if n > uint64(len(d.buf)-d.off) {
		return nil, errTruncated
	}
	out := make([]byte, n)
	copy(out, d.buf[d.off:d.off+int(n)])
	d.off += int(n)
	return out, nil
}

func (d *decoder) str() (string, error) {
	b, err := d.bytes()
	if err != nil {
		return "", err
	}
	if !utf8.Valid(b) {
		return "", errors.New("postcard: invalid utf-8 in string")
	}
	return string(b), nil
}

func (d *decoder) done() error {
	if d.off != len(d.buf) {
		return fmt.Errorf("postcard: %d trailing bytes", len(d.buf)-d.off)
	}
	return nil
}
