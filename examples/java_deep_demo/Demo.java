import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/** Public, intentionally insecure fixture for CrySentry deep-evidence demos. */
public class Demo {
    public static void main(String[] args) throws Exception {
        byte[] key = new byte[16];
        new Random(7).nextBytes(key);
        SecretKeySpec spec = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, spec);
        System.out.println(cipher.getAlgorithm());
    }
}
