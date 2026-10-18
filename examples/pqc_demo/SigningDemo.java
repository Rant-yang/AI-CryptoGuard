package demo;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;

/** Public demonstration code: an RSA signature consumer, with no stored key. */
public final class SigningDemo {
    private SigningDemo() {}

    public static byte[] sign(byte[] message) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(pair.getPrivate());
        signer.update(message);
        return signer.sign();
    }
}
