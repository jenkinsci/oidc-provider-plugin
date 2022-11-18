package io.jenkins.plugins.oidc_provider;

import hudson.util.Secret;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class ECSecretKeyPair implements SecretKeyPair {
    private static final long serialVersionUID = 2448941858110252020L;

    /**
     * Encrypted base64 encoding of a private key in {@link PKCS8EncodedKeySpec}
     */
    private final Secret privateKey;

    /**
     * Encrypted base64 encoding of a public key in {@link X509EncodedKeySpec}
     */
    private final Secret publicKey;

    public ECSecretKeyPair(KeyPair keyPair) {
        this.privateKey = Secret.fromString(Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));
        this.publicKey = Secret.fromString(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
    }

    @Override
    public KeyPair toKeyPair() throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("EC");

        PrivateKey priv = keyFactory.generatePrivate(
            new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKey.getPlainText())));

        PublicKey pub = keyFactory.generatePublic(
            new X509EncodedKeySpec(Base64.getDecoder().decode(publicKey.getPlainText())));

        return new KeyPair(pub, priv);
    }

}
