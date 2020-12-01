package RSA

import (
	"CryptoCode/Util"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
)

const RSA_PRIVATEKEY  = "RSA PRIVATEKEY"
const RSA_PUBLICKEY  = "RSA PUBLICKEY"

//该方法用于将生成的私钥跟用要保存在文件中，进行持久化保存。
func generitePirPemKey( pir *rsa.PrivateKey,file_name string) error {
	blockBytes := x509.MarshalPKCS1PrivateKey(pir)
	file, err := os.Create("rsa_pri"+file_name+".pem")
	if err != nil {
		fmt.Println(err.Error())
		return err
	}
	b := pem.Block{
		Type:  RSA_PRIVATEKEY,
		Bytes: blockBytes,
	}
	return pem.Encode(file, &b)
}

//该方法用于将生成的公钥跟用要保存在文件中
func generatePubKey(pub *rsa.PublicKey,file_name string) error {
	pubBytes := x509.MarshalPKCS1PublicKey(pub)
	file,err := os.Create("rsa_pub"+file_name+".pem")
	if err != nil {
		return err
	}
	b := pem.Block{
		Type:    RSA_PUBLICKEY,
		Bytes:   pubBytes,
	}
	return pem.Encode(file,&b)
}

//生成一对密钥并以pem文件格式进行保存，既生成两个文件证书
func GenerateKeysPems(file_name string) error {
	pri,err := CreatrRSAPairKeys(11)
	if err != nil {
		return err
	}
	err = generitePirPemKey(pri,file_name)
	if err != nil {
		return err
	}
	err = generatePubKey(&pri.PublicKey,file_name)
	if err != nil {
		return err
	}
	return nil
}

//改方法用于生成一对密钥
func CreatrRSAPairKeys(bits int) (*rsa.PrivateKey, error) {

	flag.IntVar(&bits, "b", 2048, "rsa密钥长度，默认为1024位")

	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}

	//publicKey := privateKey.PublicKey

	return privateKey, nil
}

//=========================公钥加密，私钥解密-->加密======================//
//使用rsa对数据进行加密返回密文
func RSAEncrypt0(pri rsa.PublicKey, data []byte) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, &pri, data)
}

//使用rsa对数据进行对数据解密返回铭文
func RSADecrypt1(pri *rsa.PrivateKey, cipher []byte) ([]byte, error) {
	return rsa.DecryptPKCS1v15(rand.Reader, pri, cipher)
}

//========================私钥签名，公钥验签-->数字签名====================//
//进行数字签名
func RSASignEncrypt0(pri *rsa.PrivateKey, data []byte) ([]byte, error) {

	hashed := Util.Sha256Hash(data)

	return rsa.SignPKCS1v15(rand.Reader, pri, crypto.SHA256, hashed)
}

//验证数字签名
func RSASignVerf1(pir rsa.PublicKey, sign []byte, data []byte) (bool, error) {

	hashed := Util.Sha256Hash(data)

	VerifyReaout := rsa.VerifyPKCS1v15(&pir, crypto.SHA256, hashed, sign)

	return VerifyReaout == nil, VerifyReaout
}
