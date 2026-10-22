package main
import "crypto/mlkem"
func k() { dk, _ := mlkem.GenerateKey768(); _ = dk }
