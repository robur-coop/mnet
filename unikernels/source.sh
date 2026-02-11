#!/bin/bash

[ ! -d "vendors" ] && mkdir vendors
[ ! -d "vendors/bstr" ] && opam source bstr --dir vendors/bstr
[ ! -d "vendors/digestif" ] && opam source digestif --dir vendors/digestif
[ ! -d "vendors/gmp" ] && opam source gmp --dir vendors/gmp
[ ! -d "vendors/kdf" ] && opam source kdf --dir vendors/kdf
[ ! -d "vendors/mirage-crypto-rng-mkernel" ] && opam source mirage-crypto-rng-mkernel --dir vendors/mirage-crypto-rng-mkernel
[ ! -d "vendors/mkernel" ] && opam source mkernel --dir vendors/mkernel
[ ! -d "vendors/mnet" ] && opam source mnet --dir vendors/mnet
[ ! -d "vendors/utcp" ] && opam source utcp --dir vendors/utcp
