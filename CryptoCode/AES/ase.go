package AES

import (
	"CryptoCode/Util"
	"crypto/aes"
	"crypto/cipher"
)

//AES加密
func AESEncrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	originData := Util.PKCS5EndPadding(data, block.BlockSize())

	mode := cipher.NewCBCEncrypter(block, key)
	dst := make([]byte, len(originData))
	mode.CryptBlocks(dst, originData)

	return dst, nil

}

//AES解密
func AESDecrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockMode := cipher.NewCBCDecrypter(block, key)
	originData := make([]byte, len(data))
	blockMode.CryptBlocks(originData, data)

	return originData, nil
}
