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

var (
	constW, wrev    [constN]ringelt
	wsqrt, wsqrtRev [constN / 2]ringelt
	revN            ringelt
)

func euclid(rn ringelt) ringelt {
	n := int(rn)
	m := constQ
	a0 := 1
	a1 := 0
	b0 := 0
	b1 := 1
	for n != 0 {
		a0, a1 = a1, a0-(m/n)*a1
		b0, b1 = b1, b0-(m/n)*b1
		m, n = n, m%n
	}
	if b0 > constQ {
		b0 %= constQ
	}
	for b0 < 0 {
		b0 += constQ
	}
	return ringelt(b0)
}

func init() {
	var v ringelt = 1
	var primN ringelt
	switch constQ {
	case 12289:
		primN = 7
	case 59393:
		primN = 3
	default:
		panic("unknown Q")
	}

	for i := range constW {
		constW[i] = v
		wrev[i] = euclid(v) // x= 1/v <=> v*x+q*y=1
		if mulMOD(wrev[i], v) != 1 {
			panic("invalid wrev")
		}
		v = mulMOD(v, primN*primN)
	}

	v = primN
	for i := range wsqrt {
		wsqrt[i] = v
		wsqrtRev[i] = euclid(v) // x= 1/v <=> v*x+q*y=1
		if mulMOD(wsqrtRev[i], v) != 1 {
			panic("invalid wrev")
		}
		// v = mulMOD(v, 9)
		v = mulMOD(v, primN*primN)
	}
	revN = euclid(constN)
}
