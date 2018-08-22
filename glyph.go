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
	"context"
	"errors"
	"time"

	"github.com/AidosKuneen/numcpu"
)

/*NewSK generates signing key (s1,s2), stored in physical form */
func NewSK() (*SigningKey, error) {
	sk := &SigningKey{}
	var err error
	sk.s1, err = sampleGLPSecret()
	if err != nil {
		return nil, err
	}
	sk.s2, err = sampleGLPSecret()
	return sk, err
}

/*PK takes a signing key stored in physical space and computes the public key in physical space */
/*points a1, a2 are stored in FFT space */
func (sk *SigningKey) PK() *Publickey {
	pk := &Publickey{}
	s1 := sk.s1
	s2 := sk.s2
	ntt(&s1)
	ntt(&s2)
	pk.t = pointwiseMulAdd(constA, s1, s2)
	invNtt(&pk.t)
	return pk
}

/*Sign signs a message as (z,c) where z is a ring elt in physical form, and c is a hash output encoded as a sparse poly */
func (sk *SigningKey) Sign(message []byte) (*Signature, error) {
	type result struct {
		err error
		sig *Signature
	}
	notify := make(chan *result, numcpu.NumCPU())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for i := 0; i < numcpu.NumCPU(); i++ {
		go func() {
			var y1, y2 [constN]ringelt
			crand := newCrand()
			/*sample y1,y2 randomly, and repeat until they pass rejection sampling*/
			j := 0
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				for i := 0; i < constN; i++ {
					for {
						y1[i] = ringelt(crand.get16()) /*get 32 bits of random */
						y1[i] &= ^(^0 << (bBits + 1))  /*take bottom (B_BITS + 1) bits */
						if y1[i] <= 2*constB+1 {
							break
						}
					}
					for {
						y2[i] = ringelt(crand.get16()) /*get 32 bits of random */
						y2[i] &= ^(^0 << (bBits + 1))  /*take bottom (B_BITS + 1) bits */
						if y2[i] <= 2*constB+1 {
							break
						}
					}
					j += 4
					if y1[i] > constB {
						y1[i] = constQ - (y1[i] - constB)
					}
					if y2[i] > constB {
						y2[i] = constQ - (y2[i] - constB)
					}
				}
				// sig, err = sk.deterministicSign(y1, y2, message)
				sig, err := sk.deterministicSign(y1, y2, message)
				if err == nil {
					notify <- &result{
						sig: sig,
					}
					return
				}
			}
		}()
	}
	select {
	case r := <-notify:
		return r.sig, r.err
	case <-time.After(time.Minute):
		return nil, errors.New("timeout while signing")
	}
}

/*signs a message for a fixed choice of ephemeral secret y in physcial space
returns error according to success or failure in doing so (due to rejection sampling)*/
func (sk *SigningKey) deterministicSign(y1, y2 [constN]ringelt, message []byte) (*Signature, error) {
	var signature Signature
	y1fft := y1
	y2fft := y2
	ntt(&y1fft)
	ntt(&y2fft)

	/*ay1_y2 = a y1 + y2*/
	ay1y2 := pointwiseMulAdd(constA, y1fft, y2fft)
	invNtt(&ay1y2)

	ay1y2rounded := ay1y2
	kfloor(&ay1y2rounded)

	/*round and hash u*/
	hashOutput := hash(ay1y2rounded, message)

	var err error
	signature.c, err = encodeSparse(hashOutput)
	if err != nil {
		return nil, err
	}

	/*z_1 = y_1 + s_1 c*/
	signature.z1 = sparseMul(sk.s1, signature.c)
	signature.z1 = pointwiseAdd(signature.z1, y1)

	/*rejection sampling on z_1*/
	for i := 0; i < constN; i++ {
		if abs(signature.z1[i]) > (constB - omega) {
			return nil, errors.New("rejected")
		}
	}

	/*z_2 = y_2 + s_2 c*/
	signature.z2 = sparseMul(sk.s2, signature.c)
	signature.z2 = pointwiseAdd(signature.z2, y2)

	/*rejection sampling on z_2*/
	for i := 0; i < constN; i++ {
		if abs(signature.z2[i]) > constB-omega {
			return nil, errors.New("rejected")
		}
	}

	/*compression of a*z1 - t*c = (a*y1+y2) - z2*/
	az1tc := pointwiseSub(ay1y2, signature.z2)

	/*signature compression*/
	for i := 0; i < constN; i++ {
		signature.z2[i], err = compressCoefficient(az1tc[i], signature.z2[i])
		if err != nil {
			return nil, err
		}
	}

	return &signature, nil
}

//Verify veriris the signature.
func (pk *Publickey) Verify(sig *Signature, message []byte) error {
	for i := 0; i < constN; i++ {
		if abs(sig.z1[i]) > (constB - omega) {
			return errors.New("invalid coeeficient")
		}
		if abs(sig.z2[i]) > (constB - omega) {
			return errors.New("invalid coeeficient")
		}
	}
	z1 := sig.z1
	z2 := sig.z2
	ntt(&z1)
	ntt(&z2)
	h := pointwiseMulAdd(constA, z1, z2)
	invNtt(&h)
	tc := sparseMul(pk.t, sig.c)
	h = pointwiseSub(h, tc)
	kfloor(&h)
	hashOutput := hash(h, message)
	ctest, err := encodeSparse(hashOutput)
	if err != nil {
		return err
	}
	for i := 0; i < omega; i++ {
		if ctest[i].pos != sig.c[i].pos {
			return errors.New("invalid signature(pos)")
		}
		if ctest[i].sign != sig.c[i].sign {
			return errors.New("invalid signature(sign)")
		}
	}
	return nil
}
