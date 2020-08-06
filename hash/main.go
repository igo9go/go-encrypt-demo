package main

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

func main() {
	str := "1234"
	fmt.Println(md5C(str))
	fmt.Println(sha256C(str))
}

func md5C(str string) string  {
	h := md5.New()
	h.Write([]byte(str))
	return hex.EncodeToString(h.Sum(nil))
}

func sha256C(str string) string    {
	h :=sha256.New()
	h.Write([]byte(str))
	return hex.EncodeToString(h.Sum(nil))
}
