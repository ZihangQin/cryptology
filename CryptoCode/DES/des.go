package DES

import (
	"CryptoCode/Util"
	"crypto/cipher"
	"crypto/des"
)

func DESEnCrypt(data []byte,key []byte) ([]byte, error)  {
	block,err := des.NewCipher(key)
	if err != nil {
		return nil,err
	}
	originText := Util.PKCS5EndPadding(data,block.BlockSize())
	mode := cipher.NewCBCEncrypter(block, key)
	cipherTxt := make([]byte,len(originText))
	mode.CryptBlocks(cipherTxt, originText)
	return cipherTxt,nil

}

func DESDeCrypt(data []byte,key []byte) ([]byte, error) {
	block,err := des.NewCipher(key)
	if err != nil {
		return nil,err
	}
	originalText := make([]byte,len(data))
	mode := cipher.NewCBCDecrypter(block,key)
	cipherText := make([]byte,len(key))
	mode.CryptBlocks(originalText, cipherText)
	return originalText,nil
}
