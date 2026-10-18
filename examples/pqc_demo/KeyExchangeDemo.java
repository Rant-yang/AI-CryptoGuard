package demo;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import javax.crypto.KeyAgreement;

/** Public demonstration code: an ECDH key agreement consumer. */
public final class KeyExchangeDemo {
    private KeyExchangeDemo() {}

    public static byte[] agree() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(256);
        KeyPair alice = generator.generateKeyPair();
        KeyPair bob = generator.generateKeyPair();
        KeyAgreement exchange = KeyAgreement.getInstance("ECDH");
        exchange.init(alice.getPrivate());
        exchange.doPhase(bob.getPublic(), true);
        return exchange.generateSecret();
    }
}
