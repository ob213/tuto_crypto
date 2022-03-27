package ob.gonzo;

import ob.gonzo.encryption.CryptoUtilImpl;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class TestRSA {
    public static void main(String[] args) throws Exception {

        /*
        * Private Key: MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAqDofVHEI7GnmNN6Ju3oT0IR2H1NlSOBdR9vLCYG30HiMFh92vFLa6E3FFgmpp8095YNO9UBbr5qlhrF/giCeBQIDAQABAkAEHV/Uzer89V4nHuZZipPffs3w2DZbAPnnHw4pTl3zoGUNy++si2+YqB++DLIoOLh9N8h7xaqwXpkknF4AasLBAiEA0SZ1RWxI8SH1q9lkAdVUroSxvJnzZDRDmLFAyzMqENECIQDN6PV/ApD/Uc6xPn5WEZJ6TrqfXQiKj2qch+dsekem9QIgChm+XhztpN+L+sGj58bCsS7tWntg2rz/ardctrOA25ECIAbDtXTzt6G7pUerXuki8KX1+imMG+C5b24vBMpKhhoVAiEAuhsnnBr+Ah/GXn7ygOpuBqQV2ITLuBDwBjXNhsVBkuA=
           Public Key: MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKg6H1RxCOxp5jTeibt6E9CEdh9TZUjgXUfbywmBt9B4jBYfdrxS2uhNxRYJqafNPeWDTvVAW6+apYaxf4IgngUCAwEAAQ==
        * */
        String publicKeyBase64 = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKg6H1RxCOxp5jTeibt6E9CEdh9TZUjgXUfbywmBt9B4jBYfdrxS2uhNxRYJqafNPeWDTvVAW6+apYaxf4IgngUCAwEAAQ==";
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        byte[] decodeKey = Base64.getDecoder().decode(publicKeyBase64);
        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(decodeKey));

        String data = "Voici un message clair à chiffrer";
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes());
        System.out.println("Encrypted Message: "+Base64.getEncoder().encodeToString(encryptedBytes));
    }
}
