package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image/png"
	"github.com/pquerna/otp/totp"
)

func main() {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "TestIssuer",
		AccountName: "user1",
	})
	if err != nil {
		fmt.Println("Error generating:", err)
		return
	}

	img, err := key.Image(200, 200)
	if err != nil {
		fmt.Println("Error image:", err)
		return
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		fmt.Println("Error png:", err)
		return
	}

	base64Data := base64.StdEncoding.EncodeToString(buf.Bytes())
	fmt.Println("data:image/png;base64," + base64Data[:50] + "...")
}
