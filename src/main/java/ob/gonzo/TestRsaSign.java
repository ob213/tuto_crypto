package ob.gonzo;

import ob.gonzo.encryption.CryptoUtilImpl;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class TestRsaSign {
    public static void main(String[] args) throws Exception{
        CryptoUtilImpl cryptoUtil = new CryptoUtilImpl();
        PrivateKey privateKey = cryptoUtil.privateKeyFromJKS("obarro.jks", "123456", "obarro");
        String data = "This is my message";
        String signature = cryptoUtil.rsaSign(data.getBytes(), privateKey);
        String documentSigned = data+"_.._"+signature;
        System.out.println(documentSigned);
        System.out.println("==================================================================================");
        System.out.println("Signature verification");
        String signedDocReceived = "This is my message_.._Nz9NGP4NBmiF1TA/TiZuQ7X8j81nRw0JTTAsijqkJDWXj87WWTqeS773eHbDoBRtwYkqqsMgY0XzOymAN7VrJXqXr885SA8mZp5oCuo4SLQFS/PY3FBKPoyxmO+bUZmo/GTOV2qgpOlc9pfpd9DTqZJ407M8QB28+vRaZiqhhttNjsBoBD2piAziRrzgrD0P+90+AAh1xLzQEtHKoYj88ADSsREOVUPYwyJwVGn6E3d/DMIGyJrdZRZFK/oBAwQJUbbjD+Tj6MbghIQJtmJPum4I5hxOJ+SpJWD9vl9Y1HUZGqfdbxUMj8r8UO3UNN8lPYL4/9h9WIcF1gXmg/+B1Q==";
        PublicKey publicKey = cryptoUtil.publicKeyFromCerificates("myCertificate.cert");
        boolean b = cryptoUtil.rsaVerify(signedDocReceived, publicKey);
        System.out.println(b?"Signature OK":"Signature KO");
    }
}
