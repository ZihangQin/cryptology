package Util

import (
	"crypto/md5"
	"crypto/sha256"
)

func Sha256Hash(data []byte) []byte {
	Sha256Hash := sha256.New()
	Sha256Hash.Write(data)
	 return Sha256Hash.Sum(nil)
}

func Md5Hash(data []byte) []byte {
	Md5Hash := md5.New()
	Md5Hash.Write(data)
	return Md5Hash.Sum(nil)
}