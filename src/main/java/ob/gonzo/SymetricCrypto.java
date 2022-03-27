package ob.gonzo;

import ob.gonzo.encryption.CryptoUtilImpl;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

public class SymetricCrypto {
    public static void main(String[] args) throws Exception {
        CryptoUtilImpl cryptoUtil = new CryptoUtilImpl();
        SecretKey secretKey = cryptoUtil.generateSecretkey();
        SecretKey secretKey1 = cryptoUtil.generateSecretkeyFromString("azerty_azerty_az");
        byte[] encodedSecretKey = secretKey.getEncoded();
        System.out.println(Arrays.toString(encodedSecretKey));
        //System.out.println(new String(encodedSecretKey));
        String encodedSecretKeyStringFormat = Base64.getEncoder().encodeToString(encodedSecretKey);
        System.out.println(encodedSecretKeyStringFormat);
        System.out.println("===============================================================================================");
        String data = "My data .....";
        String encryptedData = cryptoUtil.encryptAES(data.getBytes(), secretKey1);
        System.out.println(encryptedData);
        byte[] decryptedBytes = cryptoUtil.decryptAES(encryptedData, secretKey1);
        System.out.println(new String(decryptedBytes));
    }
}
