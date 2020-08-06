package main

import (
	"crypto/cipher"
	"crypto/des"
)

// 3DES加密
func TripleDESEncrypt(src, key []byte) []byte {
	// 1. 创建并返回一个使用3DES算法的cipher.Block接口
	block, err := des.NewTripleDESCipher(key)
	if err != nil{
		panic(err)
	}
	// 2. 对最后一组明文进行填充
	src = PKCS5Padding(src, block.BlockSize())
	// 3. 创建一个密码分组为链接模式, 底层使用3DES加密的BlockMode模型
	blockMode := cipher.NewCBCEncrypter(block, key[:8])
	// 4. 加密数据
	dst := src
	blockMode.CryptBlocks(dst, src)
	return dst
}

// 3DES解密
func TripleDESDecrypt(src, key []byte) []byte {
	// 1. 创建3DES算法的Block接口对象
	block, err := des.NewTripleDESCipher(key)
	if err != nil{
		panic(err)
	}
	// 2. 创建密码分组为链接模式, 底层使用3DES解密的BlockMode模型
	blockMode := cipher.NewCBCDecrypter(block, key[:8])
	// 3. 解密
	dst := src
	blockMode.CryptBlocks(dst, src)
	// 4. 去掉尾部填充的数据
	dst = PKCS5UnPadding(dst)
	return dst
}