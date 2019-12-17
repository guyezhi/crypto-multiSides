import sun.misc.BASE64Encoder;

import java.security.SecureRandom;

import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;

/**
 * @author yu.gu
 * @date 2019/12/13 17:54
 */
public class DesCrypto {

    private static String password = "0123456789abcdef";

    /**
     *
     * @Method: encrypt
     * @Description: 加密数据
     * @param data
     * @return
     */
    public static String encrypt(String data) {
        // 对string进行BASE64Encoder转换
        byte[] bt = encryptByKey(data.getBytes(), password);
        BASE64Encoder base64en = new BASE64Encoder();
        String strs = base64en.encode(bt);
        return strs;
    }
    /**
     *
     * @Method: encrypt
     * @Description: 解密数据
     * @param data
     * @return
     */
    public static String decryptor(String data) throws Exception {
        // 对string进行BASE64Encoder转换
        sun.misc.BASE64Decoder base64en = new sun.misc.BASE64Decoder();
        byte[] bt = decrypt(base64en.decodeBuffer(data), password);
        String strs = new String(bt);
        return strs;
    }
    /**
     * 加密
     * @param datasource byte[]
     * @param key String
     * @return byte[]
     */
    private static byte[] encryptByKey(byte[] datasource, String key) {
        try{
            SecureRandom random = new SecureRandom();

            DESKeySpec desKey = new DESKeySpec(key.getBytes());
            // 创建一个密匙工厂，然后用它把DESKeySpec转换成
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
            SecretKey securekey = keyFactory.generateSecret(desKey);
            // Cipher对象实际完成加密操作
            Cipher cipher = Cipher.getInstance("DES");
            // 用密匙初始化Cipher对象
            cipher.init(Cipher.ENCRYPT_MODE, securekey, random);
            // 现在，获取数据并加密
            // 正式执行加密操作
            return cipher.doFinal(datasource);
        }catch(Throwable e){
            e.printStackTrace();
        }
        return null;
    }
    /**
     * 解密
     * @param src byte[]
     * @param key String
     * @return byte[]
     * @throws Exception
     */
    private static byte[] decrypt(byte[] src, String key) throws Exception {
        //  DES算法要求有一个可信任的随机数源
        SecureRandom random = new SecureRandom();
        //  创建一个DESKeySpec对象
        DESKeySpec desKey = new DESKeySpec(key.getBytes());
        //  创建一个密匙工厂
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
        //  将DESKeySpec对象转换成SecretKey对象
        SecretKey securekey = keyFactory.generateSecret(desKey);
        //  Cipher对象实际完成解密操作
        Cipher cipher = Cipher.getInstance("DES");
        //  用密匙初始化Cipher对象
        cipher.init(Cipher.DECRYPT_MODE, securekey, random);
        //  真正开始解密操作
        return cipher.doFinal(src);
    }


    public static void main(String[] args) throws Exception {
        String src = "1234qwer";

        String encrypt = encrypt(src);
        System.out.println(encrypt);
        String decrypt = decryptor(encrypt);
        System.out.println(decrypt);
    }
}
