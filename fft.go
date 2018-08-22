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

/*
We use Gentleman-Sande, decimation-in-frequency FFT, for the forward FFT.
We premultiply x by the 2n'th roots of unity to affect a Discrete Weighted Fourier Transform,
so when we apply pointwise multiplication we obtain the negacyclic convolution, i.e. multiplication
modulo x^n+1.
Note that we will not perform the usual scambling / bit-reversal procedure here because we will invert
the fourier transform using decimation-in-time.
*/

func fftTwistedForward(x *[constN]ringelt) {
	//Pre multiplication for twisted FFT
	j := 0
	for i := 0; i < constN>>1; i++ {
		x[j] = mulMOD(x[j], constW[i])
		j++
		x[j] = mulMOD(x[j], wsqrt[i])
		j++
	}

	var step ringelt = 1
	for m := constN >> 1; m >= 1; m >>= 1 {
		var index ringelt
		for j := 0; j < m; j++ {
			m2 := m << 1
			for i := j; i < constN; i += m2 {
				t0 := addMOD(x[i], x[i+m])
				t1 := subMOD(x[i], x[i+m])
				x[i+m] = mulMOD(t1, constW[index])
				x[i] = t0
			}
			index = subMODn(index, step)
		}
		step <<= 1
	}
}

/*
We use Cooley-Tukey, decimation-in-time FFT, for the inverse FFT.
We postmultiply x by the inverse of the 2n'th roots of unity * n^-1 to affect a Discrete Weighted Fourier Transform,
so when we apply pointwise multiplication we obtain the negacyclic convolution, i.e. multiplication
modulo x^n+1.
Note that we will not perform the usual scambling / bit-reversal procedure here because we will the forward
fourier transform is using decimation-in-frequency.
*/
func fftTwistedBackward(x *[constN]ringelt) {
	var step ringelt = constN >> 1
	for m := 1; m < constN; m <<= 1 {
		var index ringelt
		for j := 0; j < m; j++ {
			m2 := m << 1
			for i := j; i < constN; i += m2 {
				t0 := x[i]
				t1 := mulMOD(x[i+m], wrev[index])
				x[i] = addMOD(t0, t1)
				x[i+m] = subMOD(t0, t1)
			}
			index = subMODn(index, step)
		}
		step >>= 1
	}

	//Post multiplication for twisted FFT
	j := 0
	for i := 0; i < constN>>1; i++ {
		x[j] = mulMOD(x[j], wrev[i])
		j++
		x[j] = mulMOD(x[j], wsqrtRev[i])
		j++
	}
}

func fftForward(x *[constN]ringelt) {
	fftTwistedForward(x)
}

func fftBackward(x *[constN]ringelt) {
	fftTwistedBackward(x)
	for i := range x {
		x[i] = mulMOD(x[i], revN)
	}
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
