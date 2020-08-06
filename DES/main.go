package main

import (
	"encoding/base64"
	"fmt"
)

func main()  {
	key := []byte("12345678")


	fmt.Println(string(DesEncrypt_CBC([]byte("aaa"), key)))

	DESText()
	AESText()
}

func DESText() {
	// 加密
	key := []byte("11111111")
	result := DesEncrypt_CBC([]byte("床前明月光, 疑是地上霜. 举头望明月, 低头思故乡."), key)
	fmt.Println(base64.StdEncoding.EncodeToString(result))
	// 解密
	result = DesDecrypt_CBC(result, key)
	fmt.Println("解密之后的数据: ", string(result))
}

func AESText() {
	// 加密
	key := []byte("1111111111111111")
	result := AESEncrypt([]byte("床前明月光, 疑是地上霜. 举头望明月, 低头思故乡."), key)
	fmt.Println(base64.StdEncoding.EncodeToString(result))
	// 解密
	result = AESDecrypt(result, key)
	fmt.Println("解密之后的数据: ", string(result))
}