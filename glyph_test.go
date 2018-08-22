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
	"testing"
)

type testvec struct {
	pk      Publickey
	sk      SigningKey
	y1      [constN]ringelt
	y2      [constN]ringelt
	sig     Signature
	message []byte
}

const signTrials = 100

//only for q=59393, b=16383
func _TestGlyph2(t *testing.T) {
	vec := testvecs[0]
	/*check that public key is derived from signing key*/
	pktest := vec.sk.PK()
	for i := 0; i < constN; i++ {
		if pktest.t[i] != vec.pk.t[i] {
			t.Error("failed to derive public key from signing key")
		}
	}

	/*check that supplied signature verifies correctly*/
	if err := vec.pk.Verify(&vec.sig, vec.message); err != nil {
		t.Error(err)
	}

	/*check that computed signature matches provided one*/
	sigtest, err := vec.sk.deterministicSign(vec.y1, vec.y2, vec.message)
	if err != nil {
		t.Error(err)
	}
	for i := 0; i < constN; i++ {
		if sigtest.z1[i] != vec.sig.z1[i] {
			t.Error("failed to produce z1 signature from test vector", sigtest.z1[i], vec.sig.z1[i], i)
		}
		if sigtest.z2[i] != vec.sig.z2[i] {
			t.Error("failed to produce z2 signature from test vector")
		}
	}
	for i := 0; i < omega; i++ {
		if sigtest.c[i].pos != vec.sig.c[i].pos {
			t.Error("failed to produce pos signature from test vector")
		}
		if sigtest.c[i].sign != vec.sig.c[i].sign {
			t.Error("failed to produce sign signature from test vector")
		}
	}

}

func TestGlyph1(t *testing.T) {
	message := []byte("testtest")

	/*print a single example*/
	t.Log("example signature")
	t.Log("message:")
	t.Log(message)
	sk, err := NewSK()
	if err != nil {
		t.Error(err)
	}
	pk := sk.PK()
	pkt1 := pk.t
	var zero [1024]ringelt
	ntt(&pk.t)
	if pk.t == zero {
		t.Fatal("pk is all zero")
	}
	invNtt(&pk.t)
	if pk.t == zero {
		t.Fatal("pk is all zero")
	}
	if pk.t != pkt1 {
		t.Log(pk.t)
		t.Log(pkt1)
		t.Fatal("invalid ntt")
	}

	t.Log("signing key:")
	t.Log(sk)
	t.Log("public key:")
	t.Log(pk)
	sig, err := sk.Sign(message)
	if err != nil {
		t.Error(err)
	}
	t.Log("signature:")
	t.Log(sig.z1)
	t.Log(sig.z2)
	t.Log(sig.c)
	if err := pk.Verify(sig, message); err != nil {
		t.Error(err)
	}
	t.Fatal()
}

func BenchmarkNtt(b *testing.B) {
	sk, err := NewSK()
	if err != nil {
		b.Error(err)
	}
	pk := sk.PK()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ntt(&pk.t)
	}
}

// func BenchmarkFft(b *testing.B) {
// 	sk, err := NewSK()
// 	if err != nil {
// 		b.Error(err)
// 	}
// 	pk := sk.PK()

// 	b.ResetTimer()
// 	for i := 0; i < b.N; i++ {
// 		fftForward(&pk.t)
// 	}
// }
func BenchmarkSign(b *testing.B) {
	message := make([]byte, 32)

	sk, err := NewSK()
	if err != nil {
		b.Error(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sk.Sign(message)
	}
}

func BenchmarkSparse(b *testing.B) {
	message := make([]byte, 32)

	sk, err := NewSK()
	if err != nil {
		b.Error(err)
	}
	sig, err := sk.Sign(message)
	if err != nil {
		b.Error(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sparseMul(sk.s1, sig.c)
	}
}

func BenchmarkNTTSparse(b *testing.B) {
	message := make([]byte, 32)

	sk, err := NewSK()
	if err != nil {
		b.Error(err)
	}
	sig, err := sk.Sign(message)
	if err != nil {
		b.Error(err)
	}
	b.ResetTimer()
	var sm [constN]ringelt
	for i := 0; i < b.N; i++ {
		for i, v := range sig.c {
			if v.sign {
				sm[i] = 1
			} else {
				sm[i] = constQ - 1
			}
		}
		ntt(&sm)
		s1 := sk.s1
		ntt(&s1)
		sm = pointwiseMul(s1, sm)
		invNtt(&sm)
	}
}

func TestNTTSpace(t *testing.T) {
	message := make([]byte, 32)

	sk, err := NewSK()
	if err != nil {
		t.Error(err)
	}
	sig, err := sk.Sign(message)
	if err != nil {
		t.Error(err)
	}
	var sm [constN]ringelt
	for _, v := range sig.c {
		if v.sign {
			sm[v.pos] = 1
		} else {
			sm[v.pos] = constQ - 1
		}
	}
	ntt(&sm)
	s1 := sk.s1
	ntt(&s1)
	sm = pointwiseMul(s1, sm)
	invNtt(&sm)

	sm2 := sparseMul(sk.s1, sig.c)
	if sm != sm2 {
		t.Log(sm)
		t.Log(sm2)
		t.Error("invalid sparsemul")
	}
}

func BenchmarkVeri(b *testing.B) {
	message := make([]byte, 32)

	sk, err := NewSK()
	if err != nil {
		b.Error(err)
	}
	sig, err := sk.Sign(message)
	if err != nil {
		b.Error(err)
	}
	pk := sk.PK()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pk.Verify(sig, message)
	}
}
func TestGlyph3(t *testing.T) {
	message := []byte("testtest")

	/*test a lot of verifications*/
	t.Log("trying ", signTrials, "independent keygen/sign/verifies")
	for i := 0; i < signTrials; i++ {
		sk, err := NewSK()
		if err != nil {
			t.Error(err)
		}
		pk := sk.PK()
		sig, err := sk.Sign(message)
		if err != nil {
			t.Error("signature failure round ", i, err)
		}
		if err := pk.Verify(sig, message); err != nil {
			t.Error("verification failure round ", i, err)
		}
	}
	t.Log("signature scheme validates across ", signTrials, "independent trials")
	t.Log("******************************************************************************************************")
}

func TestGlyph4(t *testing.T) {
	message := []byte("testtest")

	/*print a single example*/
	sk, err := NewSK()
	if err != nil {
		t.Error(err)
	}
	pk := sk.PK()
	sig, err := sk.Sign(message)
	if err != nil {
		t.Error(err)
	}

	bsk := sk.Bytes()
	bpk := pk.Bytes()
	bsig := sig.Bytes()

	sk2, err := NewSigningKey(bsk)
	if err != nil {
		t.Error(err)
	}
	pk2, err := NewPublickey(bpk)
	if err != nil {
		t.Error(err)
	}
	sig2, err := NewSignature(bsig)
	if err != nil {
		t.Error(err)
	}

	if sk2 != sk2 {
		t.Error("invalid sk serialization")
	}
	if pk2 != pk2 {
		t.Error("invalid sk serialization")
	}
	if sig.z1 != sig2.z1 {
		for i := range sig.z1 {
			t.Log(sig.z1[i], sig2.z1[i], i)
		}
		t.Error("invalid sig serialization")
	}
	if sig.z2 != sig2.z2 {
		t.Error("invalid sig serialization")
	}
	if *sig.c != *sig2.c {
		t.Error("invalid sig serialization")
	}

	t.Log(len(bsk), len(bpk), len(bsig))
}
