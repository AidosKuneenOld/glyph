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
	"errors"
	"math/big"
)

//Bytes serialize Publickey.
func (p *Publickey) Bytes() []byte {
	var r big.Int
	for _, t := range p.t {
		r.Lsh(&r, qBits)
		tt := big.NewInt(int64(t))
		r.Or(&r, tt)
	}
	return r.Bytes()
}

//NewPublickey creates an Publickey from serialized bytes.
func NewPublickey(b []byte) (*Publickey, error) {
	if len(b) != qBits*constN/8 {
		return nil, errors.New("invalid length of bytes")
	}
	var r big.Int
	r.SetBytes(b)
	p := &Publickey{}
	mask := ^(^0 << qBits)
	maskQ := big.NewInt(int64(mask))
	for i := range p.t {
		var v big.Int
		v.And(&r, maskQ)
		p.t[i] = ringelt(v.Uint64())
		r.Rsh(&r, qBits)
	}
	return p, nil
}

//Bytes serialize SigningKey.
func (s *SigningKey) Bytes() []byte {
	r := make([]byte, 2*2*constN/8)
	for i, t := range append(s.s1[:], s.s2[:]...) {
		ui := uint(i)
		if t == constQ-1 {
			t = 2
		}
		r[ui/4] |= byte(t << (ui % 4))
	}
	return r
}

//NewSigningKey creates an SiningKey from serialized bytes.
func NewSigningKey(b []byte) (*SigningKey, error) {
	if len(b) != 2*2*constN/8 {
		return nil, errors.New("invalid length of bytes")
	}
	s := &SigningKey{}
	for i := range s.s1 {
		ui := uint(i)
		d := (b[ui/4] >> (ui % 4)) & 0x3
		s.s1[i] = ringelt(d)
		if s.s1[i] == 2 {
			s.s1[i] = constQ - 1
		}
	}
	for i := range s.s2 {
		ui := uint(i) + constN/4
		d := (b[ui/4] >> (ui % 4)) & 0x3
		s.s2[i] = ringelt(d)
		if s.s2[i] == 2 {
			s.s2[i] = constQ - 1
		}
	}
	return s, nil
}

//Bytes serialize sparsePolyST.
func (s *sparsePolyST) bytes() *big.Int {
	var r big.Int
	for i := 0; i < omega; i++ {
		r.Lsh(&r, 1)
		d := 0
		if s[omega-i-1].sign {
			d = 1
		}
		tt := big.NewInt(int64(d))
		r.Or(&r, tt)
		r.Lsh(&r, nBits)
		dd := s[omega-i-1].pos
		tt = big.NewInt(int64(dd))
		r.Or(&r, tt)
	}
	return &r
}

//newSparsePoly creates an sparsePolyST from serialized bytes.
func newSparsePoly(r *big.Int) (*sparsePolyST, error) {
	var s sparsePolyST
	mask := ^(^0 << nBits)
	maskN := big.NewInt(int64(mask))
	for i := 0; i < omega; i++ {
		var v big.Int
		v.And(r, maskN)
		s[i].pos = uint16(v.Uint64())
		r.Rsh(r, nBits)
		if r.Bit(i) == 1 {
			s[i].sign = true
		}
		r.Rsh(r, 1)
	}
	return &s, nil
}

//Bytes serialize Signature.
func (s *Signature) Bytes() []byte {
	r := s.c.bytes()
	for i := 0; i < constN; i++ {
		r.Lsh(r, 2)
		d := s.z2[constN-i-1]
		switch d {
		case 0:
		case constB - omega:
			d = 1
		case constQ - (constB - omega):
			d = 2
		}
		tt := big.NewInt(int64(d))
		r.Or(r, tt)
	}
	for i := 0; i < constN; i++ {
		r.Lsh(r, bBits+1)
		d := s.z1[constN-i-1]
		if d*2 > constQ {
			d = (1 << (bBits + 1)) - (constQ - d)
		}
		tt := big.NewInt(int64(d))
		r.Or(r, tt)
	}
	return r.Bytes()
}

//NewSignature creates an sparsePolyST from serialized bytes.
func NewSignature(b []byte) (*Signature, error) {
	if len(b) != ((bBits+1+2)*constN+11*omega)/8 {
		return nil, errors.New("invalid length of bytes")
	}
	var s Signature
	var r big.Int
	r.SetBytes(b)
	mask := ^(^0 << (bBits + 1))
	maskB := big.NewInt(int64(mask))
	for i := 0; i < constN; i++ {
		var v big.Int
		s.z1[i] = ringelt(v.And(&r, maskB).Uint64())
		if s.z1[i]*2 > 1<<(bBits+1) {
			s.z1[i] = constQ - ((1 << (bBits + 1)) - s.z1[i])
		}
		r.Rsh(&r, bBits+1)
	}

	mask2 := big.NewInt(0x3)
	for i := 0; i < constN; i++ {
		var v big.Int
		d := v.And(&r, mask2).Uint64()
		switch d {
		case 0:
		case 1:
			d = constB - omega
		case 2:
			d = constQ - (constB - omega)
		}
		s.z2[i] = ringelt(d)
		r.Rsh(&r, 2)
	}
	var err error
	s.c, err = newSparsePoly(&r)
	return &s, err
}
