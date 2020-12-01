package ECC

import (
	"DataCertProject/util"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
)

//生成一个ecdsa算法的私钥
func GneerateKey() (*ecdsa.PrivateKey, error) {
	curve := elliptic.P256()
	return ecdsa.GenerateKey(curve, rand.Reader)
}

//私钥签名
func ECDSASign(pri *ecdsa.PrivateKey, data []byte) (r *big.Int, s *big.Int, err error) {
	sha256Hash := util.SHA256Hash(data)
	return ecdsa.Sign(rand.Reader, pri, sha256Hash)

}

//公钥验签
func ECSAVerify(pub ecdsa.PublicKey,r *big.Int,s *big.Int,data []byte) bool {
	hash := util.SHA256Hash(data)
	return ecdsa.Verify(&pub,hash,r,s)

}

