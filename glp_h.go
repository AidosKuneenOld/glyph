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

type ringelt uint16

const (
	glpDigestLength = 32

	constN = 1024
	nBits  = 10
	omega  = 16

	//sk:512 bytes,pk:2048 bytes, sig:2198bytes
	//4246 bytes
	// constQ = 59393
	// constB = 16383
	// bBits  = 14
	// qBits  = 16

	//sk:512 bytes,pk:1792 bytes, sig:1942 bytes
	//3737 bytes
	constQ = 12289
	constB = 4095
	bBits  = 12
	qBits  = 14
)

var constA [constN]ringelt

//Publickey of glyph signature.
type Publickey struct {
	t [constN]ringelt
}

//SigningKey of glyph signature.
type SigningKey struct {
	s1 [constN]ringelt
	s2 [constN]ringelt
}

type sparsePoly struct {
	pos  uint16
	sign bool
}

type sparsePolyST [omega]sparsePoly

//Signature of glyph signature.
type Signature struct {
	z1 [constN]ringelt
	z2 [constN]ringelt
	c  *sparsePolyST
}

func sign(x ringelt) int {
	if x == 0 {
		return 0
	}
	if 2*x <= constQ {
		return 1
	}
	return -1
}

func abs(x ringelt) ringelt {
	if 2*uint32(x) <= constQ {
		return x
	}
	return constQ - x
}

func neg(x ringelt) ringelt {
	return constQ - x
}

func addMOD(a, b ringelt) ringelt {
	x := uint32(a) + uint32(b)
	if x >= constQ {
		x -= constQ
	}
	return ringelt(x)
}

func subMOD(a, b ringelt) ringelt {
	x := uint32(a) + uint32(constQ-b)
	if x >= constQ {
		x -= constQ
	}
	return ringelt(x)
}

func mulMOD(a, b ringelt) ringelt {
	return ringelt((uint32(a) * uint32(b)) % constQ)
}

func subMODn(a, b ringelt) ringelt {
	x := uint32(a) + uint32(constN-b)
	if x >= constN {
		x -= constN
	}
	return ringelt(x)
}

func pointwiseMul(b, e0 [constN]ringelt) [constN]ringelt {
	var v [constN]ringelt
	for i := 0; i < constN; i++ {
		v[i] = mulMOD(e0[i], b[i])
	}
	return v
}

func pointwiseAdd(b, e0 [constN]ringelt) [constN]ringelt {
	var v [constN]ringelt
	for i := 0; i < constN; i++ {
		v[i] = addMOD(e0[i], b[i])
	}
	return v
}

func pointwiseSub(b, e0 [constN]ringelt) [constN]ringelt {
	var v [constN]ringelt
	for i := 0; i < constN; i++ {
		v[i] = subMOD(b[i], e0[i])
	}
	return v
}

/* Pointwise multiplication and addition in the ring.
   All done in the FFT / CRT domain. */
func pointwiseMulAdd(b, e0, e1 [constN]ringelt) [constN]ringelt {
	var v [constN]ringelt
	for i := 0; i < constN; i++ {
		v[i] = mulMOD(e0[i], b[i])
		v[i] = addMOD(v[i], e1[i])
	}
	return v
}
