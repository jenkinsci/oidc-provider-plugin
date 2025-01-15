package io.jenkins.plugins.oidc_provider;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.cloudbees.plugins.credentials.CredentialsScope;
import io.jenkins.plugins.oidc_provider.Keys.AlgorithmType;
import io.jenkins.plugins.oidc_provider.Keys.SupportedKeyAlgorithm;
import java.util.Arrays;
import java.util.Collection;
import java.util.stream.Collectors;
import net.sf.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class EncodeJwkWithRsaTest {

    @Parameters(name = "{0}") public static Collection<SupportedKeyAlgorithm> data(){
        return Arrays.stream(SupportedKeyAlgorithm.values()).filter(a -> a.getType() == AlgorithmType.RSA).collect(Collectors.toList());
    }

    private final SupportedKeyAlgorithm algorithm;

    public EncodeJwkWithRsaTest(SupportedKeyAlgorithm algorithm) {this.algorithm = algorithm;}

    @Test public void encodeKey() {
        String keyId = "cred";
        IdTokenStringCredentials cred = new IdTokenStringCredentials(CredentialsScope.GLOBAL, keyId, null, algorithm);

        JSONObject key = Keys.key(cred);

        assertEquals(keyId, key.getString("kid"));
        assertEquals("RSA", key.getString("kty"));
        assertEquals(algorithm.name(), key.getString("alg"));
        assertEquals("sig", key.getString("use"));
        assertTrue(key.containsKey("e"));
        assertTrue(key.containsKey("n"));
    }
}
