package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"fmt"
)

// https://tools.ietf.org/html/rfc4226
var doubleDigits = []int{0, 2, 4, 6, 8, 1, 3, 5, 7, 9}
var digitsPower = []int{1, 10, 100, 1000, 10000, 100000, 1000000, 10000000}

func main() {
	secret := []byte("12345678901234567890")
	codeDigits := 6

	for i := 0; i < 10; i++ {
		movingFactor := i
		fmt.Println(movingFactor, "->", otp(secret, movingFactor, codeDigits, false, -1))
	}
}

func hmacSHA1(key, msg []byte) []byte {
	mac := hmac.New(sha1.New, key)
	mac.Write(msg)
	return mac.Sum(nil)
}

func otp(
	secret []byte, // The shared secret.
	movingFactor int, // The counter, time or other value that changes on a per user basis.
	codeDigits int, // The number of digits in the OTP, not including the checksum, if any.
	addChecksum bool, // A flag that indicates if a checksum digit should be appended to the OTP.
	truncationOffset int,
) string {
	var digits int
	if addChecksum {
		digits = codeDigits + 1
	} else {
		digits = codeDigits
	}

	text := make([]byte, 8)
	for i := len(text) - 1; i >= 0; i-- {
		text[i] = byte(movingFactor & 0xff)
		movingFactor >>= 8
	}

	hash := hmacSHA1(secret, text)
	offset := int(hash[len(hash)-1] & 0xf)
	if (0 <= truncationOffset) && (truncationOffset < len(hash)-4) {
		offset = truncationOffset
	}
	binary := int(hash[offset]&0x7f)<<24 |
		int(hash[offset+1]&0xff)<<16 |
		int(hash[offset+2]&0xff)<<8 |
		int(hash[offset+3]&0xff)
	otp := binary % digitsPower[codeDigits]
	if addChecksum {
		otp = (otp * 10) + calcChecksum(otp, codeDigits)
	}
	return fmt.Sprintf("%0*d", digits, otp)

}

func calcChecksum(num, digits int) int {
	var doubleDigit bool
	total := 0

	for 0 < digits {
		digits--
		digits = num % 10
		num /= 10
		if doubleDigit {
			digits = doubleDigits[digits]
		}
		total += digits
		doubleDigit = !doubleDigit
	}
	result := total % 10
	if result > 0 {
		return 10 - result
	}
	return result
}
