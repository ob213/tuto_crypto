package ob.gonzo;

import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class TestRSADecrypt {
    public static void main(String[] args) throws Exception {

        /*
        * Private Key: MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAqDofVHEI7GnmNN6Ju3oT0IR2H1NlSOBdR9vLCYG30HiMFh92vFLa6E3FFgmpp8095YNO9UBbr5qlhrF/giCeBQIDAQABAkAEHV/Uzer89V4nHuZZipPffs3w2DZbAPnnHw4pTl3zoGUNy++si2+YqB++DLIoOLh9N8h7xaqwXpkknF4AasLBAiEA0SZ1RWxI8SH1q9lkAdVUroSxvJnzZDRDmLFAyzMqENECIQDN6PV/ApD/Uc6xPn5WEZJ6TrqfXQiKj2qch+dsekem9QIgChm+XhztpN+L+sGj58bCsS7tWntg2rz/ardctrOA25ECIAbDtXTzt6G7pUerXuki8KX1+imMG+C5b24vBMpKhhoVAiEAuhsnnBr+Ah/GXn7ygOpuBqQV2ITLuBDwBjXNhsVBkuA=
           Public Key: MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKg6H1RxCOxp5jTeibt6E9CEdh9TZUjgXUfbywmBt9B4jBYfdrxS2uhNxRYJqafNPeWDTvVAW6+apYaxf4IgngUCAwEAAQ==
        * */
        String privateKeyBase64 = "MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAqDofVHEI7GnmNN6Ju3oT0IR2H1NlSOBdR9vLCYG30HiMFh92vFLa6E3FFgmpp8095YNO9UBbr5qlhrF/giCeBQIDAQABAkAEHV/Uzer89V4nHuZZipPffs3w2DZbAPnnHw4pTl3zoGUNy++si2+YqB++DLIoOLh9N8h7xaqwXpkknF4AasLBAiEA0SZ1RWxI8SH1q9lkAdVUroSxvJnzZDRDmLFAyzMqENECIQDN6PV/ApD/Uc6xPn5WEZJ6TrqfXQiKj2qch+dsekem9QIgChm+XhztpN+L+sGj58bCsS7tWntg2rz/ardctrOA25ECIAbDtXTzt6G7pUerXuki8KX1+imMG+C5b24vBMpKhhoVAiEAuhsnnBr+Ah/GXn7ygOpuBqQV2ITLuBDwBjXNhsVBkuA=";
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        byte[] decodeKey = Base64.getDecoder().decode(privateKeyBase64);
        PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decodeKey));
        String encryptedData = "OeObQSAo6fp+ImKEyIRuSSvAs/CSYEHAFoeasywNhwcK/p0nzV+PWarUc3NsR8Ygpa6l9ATHx2jIWoaO5p8MoA==";
        System.out.println("Encrypted Message: "+encryptedData);
        byte[] decodeEncryptedData = Base64.getDecoder().decode(encryptedData);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(decodeEncryptedData);
        System.out.println("Decrypted Bytes: ");
        System.out.println(new String(decryptedBytes));
    }
}
