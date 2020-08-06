package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"fmt"
)

//
func DesEncrypt_CBC(src, key []byte) []byte {
	// 1.创建并返回一个使用des算法的cipher.Block接口
	block, err := des.NewCipher(key)
	if err != nil {
		panic(err)
	}

	//对最后一个明文分组 进行填充
	src = PKCS5Padding(src, block.BlockSize())

	//创建一个密码分组为链接模式的, 底层使用DES加密的BlockMode接口
	//    参数iv的长度, 必须等于b的块尺寸
	tmp := []byte("12345678")
	blockMode := cipher.NewCBCEncrypter(block, tmp)

	// 加密连续的数据块
	dst := make([]byte, len(src))
	blockMode.CryptBlocks(dst, src)

	fmt.Println("加密之后的数据: ", dst)

	// 将加密数据返回
	return dst
}

// src -> 要解密的密文
// key -> 秘钥, 和加密秘钥相同, 大小为: 8byte
func DesDecrypt_CBC(src, key []byte) []byte {
	block, err := des.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// 创建一个密码分组为链接模式的, 底层使用DES解密的BlockMode接口
	tmp := []byte("helloAAA")
	blockMode := cipher.NewCBCDecrypter(block, tmp)

	//解密数据
	dst := src
	blockMode.CryptBlocks(src, dst)

	// 去掉最后一组填充的数据
	dst = PKCS5UnPadding(dst)

	return dst
}

// 使用pks5的方式填充
func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	// 1. 计算最后一个分组缺多少个字节
	padding := blockSize - (len(ciphertext) % blockSize)
	// 2. 创建一个大小为padding的切片, 每个字节的值为padding
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	// 3. 将padText添加到原始数据的后边, 将最后一个分组缺少的字节数补齐
	newText := append(ciphertext, padText...)
	return newText
}

// 删除pks5填充的尾部数据
func PKCS5UnPadding(origData []byte) []byte {
	// 1. 计算数据的总长度
	length := len(origData)
	// 2. 根据填充的字节值得到填充的次数   //删除填充的
	number := int(origData[length-1])
	// 3. 将尾部填充的number个字节去掉
	return origData[:(length - number)]
}
