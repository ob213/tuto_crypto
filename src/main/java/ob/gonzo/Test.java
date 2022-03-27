package ob.gonzo;

import ob.gonzo.encryption.CryptoUtilImpl;

public class Test {
    public static void main(String[] args) {
        /*String document = "This is my message>>>";
        byte[] bytes =  document.getBytes();
        System.out.println(Arrays.toString(bytes));

        String documentFormatBase64 = Base64.getEncoder().encodeToString(bytes);
        System.out.println(documentFormatBase64);
        byte[] decoded =  Base64.getDecoder().decode(documentFormatBase64);
        System.out.println(new String(decoded));

        String encodedBase64Url =  Base64.getUrlEncoder().encodeToString(document.getBytes());
        System.out.println(encodedBase64Url);*/

        CryptoUtilImpl cryptoUtil = new CryptoUtilImpl();
        String data = "Hello from Nantes>>>>>";
        String dataBase64 = cryptoUtil.encodeToBase64(data.getBytes());
        String dataBase64Url = cryptoUtil.encodeToBase64Url(data.getBytes());
        System.out.println(dataBase64);
        System.out.println(dataBase64Url);

        byte[] decodeBytes = cryptoUtil.decodeFromBase64(dataBase64);
        System.out.println(new String(decodeBytes));

        byte[] decodeBytesUrl = cryptoUtil.decodeFromBase64Url(dataBase64Url);
        System.out.println(new String(decodeBytesUrl));

        /*byte[] dataBytes = data.getBytes();
        System.out.println(Arrays.toString(dataBytes));

        String dataHex = DatatypeConverter.printHexBinary(dataBytes);
        System.out.println(dataHex);

        byte[] bytes = DatatypeConverter.parseHexBinary(dataHex);
        System.out.println(Arrays.toString(bytes));
        System.out.println(new String(bytes));*/

        String s = cryptoUtil.encodeToHex(data.getBytes());
        String s1 = cryptoUtil.encodeToHexApacheCodec(data.getBytes());
        String s2 = cryptoUtil.encodeHexNative(data.getBytes());
        System.out.println(s);
        System.out.println(s1);
        System.out.println(s2);
    }
}
