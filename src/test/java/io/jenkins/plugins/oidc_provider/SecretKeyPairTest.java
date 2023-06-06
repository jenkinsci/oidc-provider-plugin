package io.jenkins.plugins.oidc_provider;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;

import io.jenkins.plugins.oidc_provider.Keys.AlgorithmType;
import io.jenkins.plugins.oidc_provider.Keys.SupportedKeyAlgorithm;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.Collection;
import java.util.logging.Level;
import java.util.stream.Collectors;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.LoggerRule;

@RunWith(Parameterized.class)
public class SecretKeyPairTest {

    @Parameters(name = "{0}") public static Collection<SupportedKeyAlgorithm> data() {
        return Arrays.asList(SupportedKeyAlgorithm.values());
    }

    private final SupportedKeyAlgorithm algorithm;

    public SecretKeyPairTest(SupportedKeyAlgorithm algorithm) {this.algorithm = algorithm;}

    @Test public void retrieveSecretKeyPair() {
        KeyPair kp = algorithm.generateKeyPair();

        SecretKeyPair secretKeyPair = SecretKeyPair.fromKeyPair(algorithm, kp);
        assertNotNull(secretKeyPair);
    }

    @Test public void restoreKeyPair() throws Exception {
        KeyPair kp = algorithm.generateKeyPair();

        SecretKeyPair secretKeyPair = SecretKeyPair.fromKeyPair(algorithm, kp);
        KeyPair parsedKp = secretKeyPair.toKeyPair();

        assertArrayEquals(kp.getPrivate().getEncoded(), parsedKp.getPrivate().getEncoded());
        assertArrayEquals(kp.getPublic().getEncoded(), parsedKp.getPublic().getEncoded());
    }
}