package main

import (
	"fmt"
	"strconv"
)

func main() {
	a := 9
	b := 8
	var c int64 = 10
	var d int64 = 9

	s2 := strconv.FormatInt(c, 2) //10 yo 16
	fmt.Println(s2)
	s3 := strconv.FormatInt(d, 2) //10 yo 16
	fmt.Println(s3)
	fmt.Println(c ^ d)
	fmt.Println(a ^ b)

	fmt.Println(int('a'))
}
