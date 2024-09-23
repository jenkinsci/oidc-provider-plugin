package io.jenkins.plugins.oidc_provider;

import hudson.util.Secret;
import io.jenkins.plugins.oidc_provider.Keys.AlgorithmType;
import io.jenkins.plugins.oidc_provider.Keys.SupportedKeyAlgorithm;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

public class RSASecretKeyPair implements SecretKeyPair {
    private static final long serialVersionUID = -419685546892544821L;

    /**
     * Encrypted base64 encoding of a private key in {@link PKCS8EncodedKeySpec}
     */
    private final Secret privateKey;

    public RSASecretKeyPair(KeyPair keyPair) {
        this.privateKey = Secret.fromString(Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));
    }

    @Override
    public KeyPair toKeyPair() throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        RSAPrivateCrtKey priv = (RSAPrivateCrtKey) keyFactory.generatePrivate(
            new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKey.getPlainText())));

        PublicKey publicKey = keyFactory.generatePublic(
            new RSAPublicKeySpec(priv.getModulus(), priv.getPublicExponent()));

        return new KeyPair(publicKey, priv);
    }
}
