[![Build Status](https://travis-ci.org/AidosKuneen/glyph.svg?branch=master)](https://travis-ci.org/AidosKuneen/glyph)
[![GoDoc](https://godoc.org/github.com/AidosKuneen/glyph?status.svg)](https://godoc.org/github.com/AidosKuneen/glyph)
[![GitHub license](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/AidosKuneen/glyph/master/LICENSE)

GLYPH 
=====

## Overview

This is an implementation of [GLYPH](https://eprint.iacr.org/2017/766.pdf), which is
a signature scheme based on Ring-LWE. 


This software is a rewrite of a [GLYPH implementation](https://github.com/quantumsafelattices/glyph) in Golang.


## Requirements

* git
* go 1.9+

are required to compile.


## Install
    $ go get github.com/AidosKuneen/glyph


## Usage
```go
	message := []byte("some message")

	sk, err := glyph.NewSK()
	sig, err := sk.Sign(message)
	pk := sk.PK()
	err:=pk.Verify(sig, message)
```



## Performance

Using the following test environment...

```
* Compiler: go version go1.10.3 linux/amd64
* Kernel: Linux WS777 4.13.5-1-ARCH #1 SMP PREEMPT Fri Oct 6 09:58:47 CEST 2017 x86_64 GNU/Linux
* CPU:  Celeron(R) CPU G1840 @ 2.80GHz 
* Memory: 8 GB
```


For signing, it takes about 5.4 mS.
For verification, it takes about 560 uS.

```
BenchmarkSign-2              300           5439532 ns/op          251241 B/op      17532 allocs/op
BenchmarkVeri-2             2000            559481 ns/op            3605 B/op         15 allocs/op

```


## Dependencies and Licenses

This software includes a rewrite (from C++ to go)  of https://github.com/quantumsafelattices/glyph,
which is covered by "Unlicense".

```
Golang Standard Library                       BSD 3-clause License
```