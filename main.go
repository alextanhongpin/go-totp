package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"log"
	"math/big"
)

var DIGITS_POWER = []int{1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000}

func main() {
	seed := "3132333435363738393031323334353637383930"
	seed32 := "3132333435363738393031323334353637383930313233343536373839303132"
	seed64 := "31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334"

	digits := 8
	T0 := 0
	X := 30
	testTime := []int{59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000}
	testSeeds := []string{seed, seed32, seed64}
	testCrypto := []func() hash.Hash{sha1.New, sha256.New, sha512.New}

	for _, t := range testTime {
		elapsed := (t - T0) / X
		time := fmt.Sprintf("%016X", elapsed)
		for i, seed := range testSeeds {
			otp, err := generateTOTP(seed, time, digits, testCrypto[i])
			if err != nil {
				log.Fatal(err)
			}
			log.Printf("time=%s seed=%d OTP=%s", time, i, otp)
		}
	}
}

func generateTOTP(key, time string, returnDigits int, crypto func() hash.Hash) (string, error) {
	if len(time) < 16 {
		return "", errors.New("invalid time string")
	}

	msg := hexStrToBytes(time)
	k := hexStrToBytes(key)

	mac := hmac.New(crypto, k)
	mac.Write(msg)
	hash := mac.Sum(nil)

	offset := hash[len(hash)-1] & 0xf
	binary := ((int(hash[offset]) & 0x7f) << 24) |
		((int(hash[offset+1]) & 0xff) << 16) |
		((int(hash[offset+2]) & 0xff) << 8) |
		(int(hash[offset+3]) & 0xff)
	otp := binary % DIGITS_POWER[returnDigits]
	return fmt.Sprintf("%0*d", returnDigits, otp), nil
}

func hexStrToBytes(src string) []byte {
	i := new(big.Int)
	i.SetString("10"+src, 16)
	b := i.Bytes()
	ret := make([]byte, len(b)-1)
	copy(ret, b[1:])
	return ret
}
