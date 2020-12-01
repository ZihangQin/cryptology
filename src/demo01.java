import sun.security.krb5.internal.crypto.Des;

import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;
import java.lang.reflect.Constructor;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;

public class demo01 {

    public static void main(String[] args) throws Exception {
        System.out.println("hello word");
        //实例化对象
        demo01 demo01 = new demo01();
        byte[] key = new byte[]{1,1,1,1,1,1,1,1};
        String a = new String("大河之剑天上来");
        byte[] msg = a.getBytes();
        demo01.encryt(key,msg);
        System.out.println(msg);




    }


    public byte[] desoperation(byte[] key , byte[] data , int mode){
        try {
            DESKeySpec spec = new DESKeySpec(key);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("DES");
            SecretKey secretKey = factory.generateSecret(spec);
            Cipher cipher = Cipher.getInstance("DES");
            cipher.init(mode, secretKey);
            cipher.doFinal(data);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }



    public  byte[] encryt(byte[] key, byte[] msg) {
        try {//存放可能出错的代码块
            DESKeySpec spec = new DESKeySpec(key);
            //工厂模式，可以根据需求，产生不同实例对象
            SecretKeyFactory factory = SecretKeyFactory.getInstance("DES");
            //将密钥进行加密
            SecretKey secretKey = factory.generateSecret(spec);
            secretKey.getEncoded();
            //实例加密算法
            Cipher cipher = Cipher.getInstance("DES");
            cipher.init(Cipher.ENCRYPT_MODE,secretKey);
           return cipher.doFinal(msg);
        } catch (InvalidKeyException e) {//处理异常
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } finally {//无论是否有异常此代码块都执行
            System.out.println("Exception is over..");
        }
        return null;
    }
    //解密
    public byte[] decrypt(byte[] key, byte[] msg){
        try {
            DESKeySpec spec = new DESKeySpec(key);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("DES");
            SecretKey secretKey = factory.generateSecret(spec);
            Cipher cipher =Cipher.getInstance("DES");
            cipher.init(Cipher.DECRYPT_MODE,secretKey);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }
}
