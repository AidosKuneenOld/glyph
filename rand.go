// Copyright (c) 2018 Aidos Developer

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package glyph

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"
)

var zero8 = make([]byte, 8)

type random struct {
	stream cipher.Stream
}

func newRandom(key, iv []byte) (*random, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &random{
		stream: cipher.NewCTR(block, iv),
	}, nil
}

func newRandom2() (*random, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	iv := make([]byte, 16)
	return newRandom(key, iv)
}

func (r *random) please(in []byte) uint64 {
	out := make([]byte, len(in))
	r.stream.XORKeyStream(out, in)
	return binary.LittleEndian.Uint64(out)
}
func (r *random) please2() uint64 {
	return r.please(zero8)
}
func sampleGLPSecrets(seed []byte) ([constN]ringelt, [constN]ringelt, error) {
	var s1, s2 [constN]ringelt
	rnd, err := newRandom(seed, make([]byte, aes.BlockSize))
	if err != nil {
		return s1, s2, err
	}
	s1, err = sampleGLPSecret(rnd)
	if err != nil {
		return s1, s2, err
	}
	s2, err = sampleGLPSecret(rnd)
	return s1, s2, err
}

func sampleGLPSecret(rnd *random) ([constN]ringelt, error) {
	var s [constN]ringelt
	randBitsUsed := 0

	rand64 := rnd.please2()
	for i := range s {
		if randBitsUsed >= 63 {
			rand64 = rnd.please2()
			randBitsUsed = 0
		}
		var rand2 uint16
		for {
			rand2 = uint16(rand64 & 3)
			rand64 >>= 2
			randBitsUsed += 2
			if rand2 != 3 {
				break
			}
		}
		switch rand2 {
		case 0:
			s[i] = 0
		case 1:
			s[i] = 1
		case 2:
			s[i] = constQ - 1
		case 3:
			panic("invalid s")
		}
	}
	return s, nil
}

type crand struct {
	buf []byte
	loc int
}

func newCrand() *crand {
	c := &crand{
		buf: make([]byte, constN*8),
	}
	if _, err := io.ReadFull(rand.Reader, c.buf); err != nil {
		panic(err)
	}
	return c
}

func (c *crand) get16() uint16 {
	if c.loc+2 >= len(c.buf) {
		if _, err := io.ReadFull(rand.Reader, c.buf); err != nil {
			panic(err)
		}
		c.loc = 0
	}
	r := binary.LittleEndian.Uint16(c.buf[c.loc:])
	c.loc += 2
	return r
}
