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
	"encoding/json"
	"errors"
	"math/big"

	"github.com/vmihailenco/msgpack"
)

//Bytes serialize Publickey.
func (p *Publickey) Bytes() []byte {
	var r big.Int
	for i := range p.t {
		r.Lsh(&r, qBits)
		t := p.t[constN-1-i]
		tt := big.NewInt(int64(t))
		r.Or(&r, tt)
	}
	return r.Bytes()
}

//NewPublickey creates an Publickey from serialized bytes.
func NewPublickey(b []byte) (*Publickey, error) {
	if len(b) != PKSize {
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
	return p, p.check()
}

//Bytes serialize SigningKey.
func (s *SigningKey) Bytes() []byte {
	var r big.Int
	for i := range s.s2 {
		r.Lsh(&r, 2)
		t := s.s2[constN-1-i]
		if t == constQ-1 {
			t = 2
		}
		tt := big.NewInt(int64(t))
		r.Or(&r, tt)
	}
	for i := range s.s1 {
		r.Lsh(&r, 2)
		t := s.s1[constN-1-i]
		if t == constQ-1 {
			t = 2
		}
		tt := big.NewInt(int64(t))
		r.Or(&r, tt)
	}
	return r.Bytes()
}

//NewSigningKey creates an SiningKey from serialized bytes.
func NewSigningKey(b []byte) (*SigningKey, error) {
	if len(b) != SKSize {
		return nil, errors.New("invalid length of bytes")
	}
	var r big.Int
	r.SetBytes(b)
	s := &SigningKey{}
	mask2 := big.NewInt(int64(3))
	for i := range s.s1 {
		var v big.Int
		v.And(&r, mask2)
		s.s1[i] = ringelt(v.Uint64())
		if s.s1[i] == 2 {
			s.s1[i] = constQ - 1
		}
		r.Rsh(&r, 2)
	}
	for i := range s.s2 {
		var v big.Int
		v.And(&r, mask2)
		s.s2[i] = ringelt(v.Uint64())
		if s.s2[i] == 2 {
			s.s2[i] = constQ - 1
		}
		r.Rsh(&r, 2)
	}
	return s, s.check()
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
		if r.Bit(0) == 1 {
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
	if len(b) != SigSize {
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
	if err != nil {
		return nil, err
	}
	return &s, s.check()
}

type publickey struct {
	T [constN]ringelt `json:"t"`
}

//MarshalJSON  marshals Publickey into valid JSON.
func (p *Publickey) MarshalJSON() ([]byte, error) {
	return json.Marshal(&publickey{
		T: p.t,
	})
}

//UnmarshalJSON  unmarshals JSON to Publickey.
func (p *Publickey) UnmarshalJSON(b []byte) error {
	var s publickey
	err := json.Unmarshal(b, &s)
	if err == nil {
		p.t = s.T
	}
	return err
}

//EncodeMsgpack  marshals Publickey into valid JSON.
func (p *Publickey) EncodeMsgpack(enc *msgpack.Encoder) error {
	return enc.Encode(&publickey{
		T: p.t,
	})
}

//DecodeMsgpack  unmarshals JSON to Publickey.
func (p *Publickey) DecodeMsgpack(dec *msgpack.Decoder) error {
	var s publickey
	err := dec.Decode(&s)
	if err == nil {
		p.t = s.T
	}
	return err
}

//SigningKey of glyph signature.
type signingKey struct {
	S1 [constN]ringelt `json:"s1"`
	S2 [constN]ringelt `json:"s2"`
}

//MarshalJSON  marshals SiningKey into valid JSON.
func (s *SigningKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(&signingKey{
		S1: s.s1,
		S2: s.s2,
	})
}

//UnmarshalJSON  unmarshals JSON to SiningKey.
func (s *SigningKey) UnmarshalJSON(b []byte) error {
	var ss signingKey
	err := json.Unmarshal(b, &ss)
	if err == nil {
		s.s1 = ss.S1
		s.s2 = ss.S2
	}
	return err
}

//EncodeMsgpack  marshals SigningKey into valid JSON.
func (s *SigningKey) EncodeMsgpack(enc *msgpack.Encoder) error {
	return enc.Encode(&signingKey{
		S1: s.s1,
		S2: s.s2,
	})
}

//DecodeMsgpack  unmarshals JSON to SigningKey.
func (s *SigningKey) DecodeMsgpack(dec *msgpack.Decoder) error {
	var ss signingKey
	err := dec.Decode(&ss)
	if err == nil {
		s.s1 = ss.S1
		s.s2 = ss.S2
	}
	return err
}
