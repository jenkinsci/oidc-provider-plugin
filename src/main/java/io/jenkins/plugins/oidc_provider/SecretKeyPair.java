package io.jenkins.plugins.oidc_provider;

import io.jenkins.plugins.oidc_provider.Keys.SupportedKeyAlgorithm;
import java.io.Serializable;
import java.security.KeyPair;

public interface SecretKeyPair extends Serializable {
    static SecretKeyPair forAlgorithm(SupportedKeyAlgorithm algorithm) {
        return SecretKeyPair.fromKeyPair(algorithm, algorithm.generateKeyPair());
    }

    static SecretKeyPair fromKeyPair(SupportedKeyAlgorithm algorithm, KeyPair keyPair) {
        switch (algorithm.getType()) {
            case RSA:
                return new RSASecretKeyPair(keyPair);
            case ELLIPTIC_CURVE:
                return new ECSecretKeyPair(keyPair);
        }

        throw new RuntimeException("Bug! Given algorithm is neither RSA nor elliptic curve! Algorithm: " + algorithm.name());
    }

    KeyPair toKeyPair() throws Exception;
}
