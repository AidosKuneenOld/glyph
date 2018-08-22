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
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sort"
)

/*hash function */
/*input: one polynomial, mu (usually itself a message digest),
  and the length of mu in bytes*/
/*output: a 256-bit hash */

func hash(u [constN]ringelt, mu []byte) [glpDigestLength]byte {
	bytesPerPoly := constN * 2
	hashInput := make([]byte, bytesPerPoly+len(mu))
	for i, x := range u {
		binary.LittleEndian.PutUint16(hashInput[2*i:], uint16(x))
	}
	copy(hashInput[bytesPerPoly:], mu)
	return sha256.Sum256(hashInput)
}

func sparseMul(a [constN]ringelt, b *sparsePolyST) [constN]ringelt {
	var vaux [2 * constN]ringelt
	var v [constN]ringelt

	/*multiply in Z[x]*/
	for _, vb := range b {
		for j := uint16(0); j < constN; j++ {
			if vb.sign {
				vaux[vb.pos+j] = addMOD(vaux[vb.pos+j], a[j])
			} else {
				vaux[vb.pos+j] = subMOD(vaux[vb.pos+j], a[j])
			}
		}
	}
	/*reduce mod x^n + 1*/
	for i := 0; i < constN; i++ {
		v[i] = subMOD(vaux[i], vaux[i+constN])
	}
	return v
}

func encodeSparse(hashOutput [glpDigestLength]byte) (*sparsePolyST, error) {
	/*key AES on hash output*/
	/*initialise AES */
	iv := make([]byte, aes.BlockSize)
	r, err := newRandom(hashOutput[:], iv)
	if err != nil {
		return nil, err
	}
	var encodeOutput sparsePolyST
	/*get OMEGA values in [0,n), each with a 0 or 1 to indicate sign*/
	rand64 := r.please2()
	randBitsUsed := 0
	for i := 0; i < omega; i++ {
		for {
			if randBitsUsed+nBits > 64 {
				rand64 = r.please2()
				randBitsUsed = 0
			}

			/*get random bits for this coefficient */
			sign := rand64 & 1
			rand64 >>= 1
			randBitsUsed++
			pos := uint16(rand64 & (^((^0) << nBits)))
			rand64 >>= nBits
			randBitsUsed += nBits

			/*get position from random*/
			if pos < constN {
				/*check we are not using this position already */
				success := true
				for j := 0; j < i; j++ {
					if pos == encodeOutput[j].pos {
						success = false
					}
				}
				if success {
					if sign == 1 {
						encodeOutput[i].sign = true
					}
					encodeOutput[i].pos = pos
					break
				}
			}
		}
	}
	sort.Slice(encodeOutput[:], func(i, j int) bool {
		return encodeOutput[i].pos < encodeOutput[j].pos
	})
	return &encodeOutput, nil
}

func kfloor(f *[constN]ringelt) {
	/*integer division by  2*K+1 where K = B - omega */
	for i, vf := range f {
		f[i] = vf / (2*(constB-omega) + 1)
	}
}

func compressCoefficient(u, v ringelt) (ringelt, error) {
	k := ringelt(constB - omega)
	if abs(v) > k {
		return 0, errors.New("invalid v")
	}
	kfloorUV := ((u + v) % constQ) / (2*k + 1)
	kfloorU := u / (2*k + 1)

	if kfloorUV == kfloorU {
		return 0, nil
	}
	if u < k {
		return constQ - k, nil
	}
	if (u >= constQ-k) && sign(v) > 0 {
		return k, nil
	}
	if kfloorUV < kfloorU {
		return constQ - k, nil
	}
	return k, nil
}
