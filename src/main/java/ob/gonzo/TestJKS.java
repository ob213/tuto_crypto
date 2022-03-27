package ob.gonzo;

import ob.gonzo.encryption.CryptoUtilImpl;

import java.security.PrivateKey;
import java.security.PublicKey;

public class TestJKS {
    public static void main(String[] args) throws Exception{
        CryptoUtilImpl cryptoUtil = new CryptoUtilImpl();
        PublicKey publicKey = cryptoUtil.publicKeyFromCerificates("myCertificate.cert");
        System.out.println(cryptoUtil.encodeToBase64(publicKey.getEncoded()));
        PrivateKey privateKey = cryptoUtil.privateKeyFromJKS("obarro.jks", "123456", "obarro");
        System.out.println(cryptoUtil.encodeToBase64(privateKey.getEncoded()));

        String data = "My secret message";
        String encrypted = cryptoUtil.encryptRSA(data.getBytes(), publicKey);
        System.out.println("Encrypted: ");
        System.out.println(encrypted);
        byte[] decryptedBytes = cryptoUtil.decryptRSA(encrypted, privateKey);
        System.out.println("Decrypted: ");
        System.out.println(new String(decryptedBytes));
    }
}
