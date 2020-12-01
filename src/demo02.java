import sun.misc.BASE64Decoder;

import javax.crypto.Cipher;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class demo02 {


    static final int RSA_LENGHT_1024 = 1024;
    static final int RSA_LENGHT_2048 = 2048;
    static String data = "一帆风顺";

    public static void main(String[] args) throws Exception {
        /**
         * rsa 对称加密算法
         */
//        //生成密钥对
//        KeyPair keyPair = createKeyPair(RSA_LENGHT_1024);
//        //1、用公钥进行加密
//        byte[] cipherTxt = encrypt(data.getBytes(), keyPair.getPublic());
//        //2、私钥进行解密
//        byte[] data = decrypt(cipherTxt, keyPair.getPrivate());
        System.out.println("程序执行结束");
        //rsa对数据进行签名

    }
    //============MD5哈希计算============//

    /**
     * 使用md5哈希算法对数据进行哈希计算
     *
     * @param data 原文数据
     * @return hash后的摘要数据
     * @throws Exception
     */
    public static byte[] md5Hash(byte[] data) throws Exception {
        MessageDigest messageDigest = MessageDigest.getInstance("MD5");
        return messageDigest.digest(data);
    }

    //=================私钥签名公钥验签================//

    /**
     * 使用rsa公钥对数据进行签名验证
     *
     * @param sinTxt 签名数据
     * @param data   原文数据
     * @param pub    公钥
     * @return 返回的是签名是否通过
     * @throws Exception
     */
    public static boolean verify(byte[] sinTxt, byte[] data, PublicKey pub) throws Exception {
        Signature signature = Signature.getInstance("MD5withRSA");
        signature.initVerify(pub);
        //对原文进行md5哈希计算
        byte[] hashCode = md5Hash(data);
        signature.update(hashCode);
        return signature.verify(sinTxt);
    }

    /**
     * rsa对数据进行签名
     *
     * @param data 哈希后的数据
     * @param pri  私钥
     * @return 签名后的数据
     * @throws Exception
     */
    public static byte[] sign(byte[] data, PrivateKey pri) throws Exception {
        Signature signature = Signature.getInstance("MD5withRSA");
        signature.initSign(pri);
        signature.update(data);//将数据更新到签名器中
        return signature.sign();//将数据进行签名
    }

    //=================公钥加密私钥解密===============//

    /**
     * 使用公钥对数据进行加密
     *
     * @param data 要加密的数据
     * @param pub  公钥
     * @return 加密后的密文
     * @throws Exception
     */
    public static byte[] encrypt(byte[] data, PublicKey pub) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, pub);
        return cipher.doFinal(data);
    }

    /**
     * 使用私钥对数据进行解密
     *
     * @param cipherTxt 加密后的数据
     * @param pri       私钥
     * @return 解密后的数据
     * @throws Exception
     */
    public static byte[] decrypt(byte[] cipherTxt, PrivateKey pri) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, pri);
        return cipher.doFinal(cipherTxt);
    }

    //=================生成密钥对====================//

    /**
     * 使用java api生成一对密钥，并返回密钥对
     *
     * @param size 密钥长度
     * @return 生成的密钥对对
     * @throws Exception
     */
    public static KeyPair createKeyPair(int size) throws Exception {
        //密钥生成器
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        //设置密钥长度
        generator.initialize(size);
        //用来生成密钥的
        KeyPair keyPair = generator.generateKeyPair();
        return keyPair;
    }

    //========加载pem文件格式的私钥和公钥=========//

    /**
     * 通过文件加载私钥的方法
     *
     * @param fileName 文件名称
     */
    public PrivateKey readPriByDerName(String fileName) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(fileName));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return factory.generatePrivate(spec);
    }

    /**
     * 通过文件加载公钥
     *
     * @param fileName 文件路径
     * @return 返回公钥
     * @throws Exception
     */
    public PublicKey readPubByDerName(String fileName) throws Exception {
        byte[] KeyBytesPub = Files.readAllBytes(Paths.get(fileName));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(KeyBytesPub);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return factory.generatePublic(spec);
    }

    /**
     * 通过文件加载私钥
     * @param fileName 文件名
     * @return 解码后的私钥字节切片
     * @throws Exception
     */
    public static PrivateKey readPriByPemName(String fileName) throws Exception {
        byte[] keyByte = Files.readAllBytes(Paths.get(fileName));
        BASE64Decoder decoder = new BASE64Decoder();
        String rsa = new String(keyByte);
        byte[] bufferFile = decoder.decodeBuffer(rsa);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(bufferFile);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return factory.generatePrivate(spec);


    }

    public static PublicKey readPubByPemName(String fileName)throws Exception{
        byte[] KeyBytesPub = Files.readAllBytes(Paths.get(fileName));
        BASE64Decoder decoder = new BASE64Decoder();
        String rsa_pub = new String(KeyBytesPub);
        byte[] buffer = decoder.decodeBuffer(rsa_pub);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(buffer);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return factory.generatePublic(spec);
    }

}


