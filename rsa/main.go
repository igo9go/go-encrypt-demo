package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
)

func GenerateRsaKey(keySize int)  {
	//使用rsa中的GenerateKey方法生成私钥
	privateKey, err := rsa.GenerateKey(rand.Reader,keySize)
	if err != nil {
		panic(err)
	}
	//通过x509标准将得到的ras私钥序列化为ASN.1 的 DER编码字符串
	derText := x509.MarshalPKCS1PrivateKey(privateKey)

	//将私钥字符串设置到pem格式块中
	block := pem.Block{
		Type: "rsa private key",
		Bytes: derText,
	}
	file, err := os.Create("private.pem")
	if err != nil {
		panic(err)
	}
	//通过pem将设置好的数据进行编码, 并写入磁盘文件中
	pem.Encode(file, &block)
	file.Close()

	// ============ 公钥 ==========
	// 1. 从私钥中取出公钥
	publicKey := privateKey.PublicKey
	// 2. 使用x509标准序列化
	derstream, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		panic(err)
	}
	// 3. 将得到的数据放到pem.Block中
	block = pem.Block{
		Type : "rsa public key",
		Bytes : derstream,
	}
	// 4. pem编码
	file, err  = os.Create("public.pem")
	if err != nil {
		panic(err)
	}
	pem.Encode(file, &block)
	file.Close()
}

func RSAEncrypt(plainText []byte,fileName string) []byte  {
	//打开文件 读取内容
	file, err := os.Open(fileName)
	if err != nil {
		panic(err)
	}

	fileInfo,err := file.Stat()
	if err != nil {
		panic(err)
	}

	buf := make([]byte, fileInfo.Size())
	file.Read(buf)
	file.Close()

	//pen解码
	block, _ := pem.Decode(buf)
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	// 断言类型转换
	pubKey := pubInterface.(*rsa.PublicKey)
	// 使用公钥加密
	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, plainText)
	if err != nil {
		panic(err)
	}
	return cipherText
}

// RSA 解密
func RSADecrypt(cipherText []byte, fileName string) []byte{
	// 1. 打开文件, 并且读出文件内容
	file, err := os.Open(fileName)
	if err != nil {
		panic(err)
	}
	fileInfo, err := file.Stat()
	if err != nil {
		panic(err)
	}
	buf := make([]byte, fileInfo.Size())
	file.Read(buf)
	file.Close()
	// 2. pem解码
	block, _ := pem.Decode(buf)
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	// 3. 使用私钥解密
	plainText, err := rsa.DecryptPKCS1v15(rand.Reader, privKey, cipherText)
	if err != nil {
		panic(err)
	}
	return plainText
}

func main()  {
	GenerateRsaKey(4096)
	src := []byte("我是小崔, 如果我死了, 肯定不是自杀...我是小崔, 如果我死了, 肯定不是自杀...我是小崔, 如果我死了, 肯定不是自杀...我是小崔, 如果我死了, 肯定不是自杀...我是小崔, 如果我死了, 肯定不是自杀...")
	cipherText := RSAEncrypt(src, "public.pem")
	//plainText := RSADecrypt(cipherText, "private.pem")
	plainText := RSADecrypt(cipherText, "private.pem")
	fmt.Println(string(plainText))

	myHash()


	mySignature, err := SignatureRSA()
	if err != nil {
		panic(err)
	}
	VerifyRSA(mySignature)
}


// 使用sha256
func myHash() {
	sha256.Sum256([]byte("hello, go"))

	// 1. 创建哈希接口对象
	myHash := sha256.New()
	// 2. 添加数据
	src := []byte("我是小崔, 如果我死了, 肯定不是自杀...我是小崔, 如果我死了, 肯定不是自杀...我是小崔, 如果我死了, 肯定不是自杀...我是小崔, 如果我死了, 肯定不是自杀...我是小崔, 如果我死了, 肯定不是自杀...")
	myHash.Write(src)
	myHash.Write(src)
	myHash.Write(src)
	// 3. 计算结果
	res := myHash.Sum(nil)
	// 4. 格式化为16进制形式
	myStr := hex.EncodeToString(res)
	fmt.Printf("%s\n", myStr)
}