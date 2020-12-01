package _DES

import (
	"CryptoCode/Util"
	"crypto/cipher"
	"crypto/des"
)

//3DES加密函数
func TripleDesEncrypt(data, key []byte) ([]byte, error) {

	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	originData := Util.PKCS5EndPadding(data, block.BlockSize())
	//originData := ZerosEndPadding(data,block.BlockSize())
	mode := cipher.NewCBCEncrypter(block, key[:8])
	dst := make([]byte, len(originData))
	//密文是dst，铭文是src
	mode.CryptBlocks(dst, originData)

	return dst, nil
}

//3DES解密函数
func TripleDesDecrypt(data, key []byte) ([]byte, error) {

	block, err := des.NewTripleDESCipher(key)
	if err != nil  {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, key)
	originData := make([]byte, len(data))
	blockMode.CryptBlocks(originData, data)

	return originData, nil

}
