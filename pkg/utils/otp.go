package utils

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

func GenerateOTP6() string {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		// fallback (แทบไม่เกิด)
		return "000000"
	}
	return fmt.Sprintf("%06d", n.Int64())
}

func GenerateOTP(maxRetry int) string {
	max := big.NewInt(1000000)

	for i := 0; i < maxRetry; i++ {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			continue // retry
		}

		return fmt.Sprintf("%06d", n.Int64())
	}

	return GenerateOTP6()
}
