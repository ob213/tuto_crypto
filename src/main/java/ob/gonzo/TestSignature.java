package ob.gonzo;

import ob.gonzo.encryption.CryptoUtilImpl;

public class TestSignature {
    public static void main(String[] args) throws Exception {
        CryptoUtilImpl cryptoUtil = new CryptoUtilImpl();
        String secret = "azzerty";
        String document = "This is my message";
        String signature = cryptoUtil.hmacSign(document.getBytes(), secret);
        String documentSigned = document+"_.._"+signature;
        System.out.println(documentSigned);
        System.out.println("====================================================================================");
        String signedDoc = "This is my message_.._OiDuX/toDD/tCPy2fUaNxKSQ6mZnbET0jWnGxfQgVNQ=";
        String sec = "azzerty";
        System.out.println("Signature verification");
        boolean signatureVerifResult = cryptoUtil.hmacVerify(signedDoc, "azzerty");
        System.out.println(signatureVerifResult==true?"Signature OK":"Signature KO");
    }
}
