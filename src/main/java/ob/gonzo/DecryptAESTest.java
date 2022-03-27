package ob.gonzo;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class DecryptAESTest {
    public static void main(String[] args) throws Exception{
        String receivedEncryptedData = "aTdsQ2ijTgJydJRWZIZPekqxuF32Pzaaatbwq9cGh9c=";
        byte[] decodeEncryptedData = Base64.getDecoder().decode(receivedEncryptedData);
        String mySecret = "azerty_azerty_az"; // 128 bit, 192, 256 => 16, 24, 32 caracteres (ici on a 128 bits donc 16 caractères)
        SecretKey secretKey = new SecretKeySpec(mySecret.getBytes(), 0,mySecret.length(), "AES");
        Cipher cipher = Cipher.getInstance("AES");

        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(decodeEncryptedData);
        System.out.println(new String(decryptedBytes));
    }
}
