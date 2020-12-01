package main

import (
	"CryptoCode/ECC"
	"CryptoCode/RSA"
	"fmt"
)

func main() {
	fmt.Println("RSA算法")

	//data:= "大喜易失言；大怒易失礼"
	//pri ,err := RSA.CreatrRSAPairKeys(11)
	//if err != nil {
	//	fmt.Println(err.Error())
	//	return
	//}
	//cipher, _  :=RSA.RSAEncrypt0(pri.PublicKey,[]byte(data))
	//fmt.Println("加密成功：",string(cipher))
	//data1,err := RSA.RSADecrypt1(pri,cipher)
	//if err != nil {
	//	fmt.Println("解密失败",err.Error())
	//}
	//fmt.Println("解密成功：",string(data1))
	//
	//
	//cipherText, err  := RSA.RSASignEncrypt0(pri,[]byte(data))
	//if err != nil {
	//	fmt.Println("数字签名失败",err.Error())
	//}
	//fmt.Println("数字签名成功：", cipherText)
	//sing := []byte("1024")
	//data2,_ := RSA.RSASignVerf1(pri.PublicKey,sing,cipherText)
	////if err != nil {
	////	fmt.Println("验证签名失败：",err.Error())
	////}
	//if data2 {
	//	fmt.Println("验签失败")
	//}else {
	//	fmt.Println("验签成功,数据未被修改")
	//}
	
	err := RSA.GenerateKeysPems("1118")
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Println("ecc算法")
	data := "1233"
	priKey, err  := ECC.GneerateKey()
	if err != nil {
		fmt.Println("私钥生成失败",err.Error())
		return
	}
	r,s,err := ECC.ECDSASign(priKey,[]byte(data))
	if err != nil {
		fmt.Println("数字签名失败",err.Error())
		return
	}
	verify := ECC.ECSAVerify(priKey.PublicKey,r,s,[]byte(data))
	if verify==true {
		fmt.Println("签名成功")
	}else {
		fmt.Println("签名失败")
	}



}
