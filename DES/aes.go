package main

import (
	"crypto/aes"
	"crypto/cipher"
)

// AES加密
func AESEncrypt(src, key []byte) []byte{
	// 1. 创建一个使用AES加密的块对象
	block, err := aes.NewCipher(key)
	if err != nil{
		panic(err)
	}
	// 2. 最后一个分组进行数据填充
	src = PKCS5Padding(src, block.BlockSize())
	// 3. 创建一个分组为链接模式, 底层使用AES加密的块模型对象
	blockMode := cipher.NewCBCEncrypter(block, key[:block.BlockSize()])
	// 4. 加密
	dst := src
	blockMode.CryptBlocks(dst, src)
	return dst
}

// AES解密
func AESDecrypt(src, key []byte) []byte{
	// 1. 创建一个使用AES解密的块对象
	block, err := aes.NewCipher(key)
	if err != nil{
		panic(err)
	}
	// 2. 创建分组为链接模式, 底层使用AES的解密模型对象
	blockMode := cipher.NewCBCDecrypter(block, key[:block.BlockSize()])
	// 3. 解密
	dst := src
	blockMode.CryptBlocks(dst, src)
	// 4. 去掉尾部填充的字
	dst = PKCS5UnPadding(dst)
	return dst
}