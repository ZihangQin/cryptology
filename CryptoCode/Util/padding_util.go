package Util

import "bytes"

//为要加密的铭文进行PKCS5尾部填充
func PKCS5EndPadding(data []byte, blockSize int) []byte {

	if len(data)%blockSize == 0 {
		return data
	}
	size := blockSize - len(data)%blockSize
	padding := bytes.Repeat([]byte{byte(size)}, size)

	return append(data, padding...)

}

//为加密铭文进行zeros尾部填充
func ZerosEndPadding(data []byte, blockSize int) []byte {

	size := blockSize - len(data)%blockSize
	padding := bytes.Repeat([]byte{byte(0)}, size)

	return append(data, padding...)

}
