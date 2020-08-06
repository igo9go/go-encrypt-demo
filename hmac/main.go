package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"fmt"
)

func main () {
	src := []byte("在消息认证码中，需要发送者和接收者之间共享密钥，而这个密钥不能被主动攻击者Mallory获取。" +
		"如果这个密钥落入Mallory手中，则Mallory也可以计算出MAC值，从而就能够自由地进行篡改和伪装攻击，" +
		"这样一来消息认证码就无法发挥作用了。")
	key := []byte("helloworld")
	hamc1 := GenerateHamc(src, key)
	bl := VerifyHamc(src, key, hamc1)
	//fmt.Printf("校验结果: %t\n", bl)
	fmt.Println(bl)
}

// 生成消息认证码
func GenerateHamc(plainText, key []byte)[]byte {
	// 1.创建哈希接口, 需要指定使用的哈希算法, 和秘钥
	myhash := hmac.New(sha1.New, key)
	// 2. 给哈希对象添加数据
	myhash.Write(plainText)
	// 3. 计算散列值
	hashText := myhash.Sum(nil)
	return hashText
}

// 验证消息认证码
func VerifyHamc(plainText, key, hashText []byte) bool {
	// 1.创建哈希接口, 需要指定使用的哈希算法, 和秘钥
	myhash := hmac.New(sha1.New, key)
	// 2. 给哈希对象添加数据
	myhash.Write(plainText)
	// 3. 计算散列值
	hamc1 := myhash.Sum(nil)

	fmt.Println(hashText, hamc1)
	// 4. 两个散列值比较
	return hmac.Equal(hashText, hamc1)
}
