/*
 * The MIT License
 *
 * Copyright 2022 CloudBees, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package io.jenkins.plugins.oidc_provider;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.domains.Domain;
import com.gargoylesoftware.htmlunit.Page;
import java.net.URL;
import java.util.logging.Level;
import jenkins.model.Jenkins;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Rule;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.LoggerRule;
import org.jvnet.hudson.test.MockAuthorizationStrategy;

public class KeysTest {

    @Rule public JenkinsRule r = new JenkinsRule();
    @Rule public LoggerRule logging = new LoggerRule().recordPackage(Keys.class, Level.FINE);

    @Test public void globalEndpoint() throws Exception {
        r.jenkins.setSecurityRealm(r.createDummySecurityRealm());
        r.jenkins.setAuthorizationStrategy(new MockAuthorizationStrategy().grant(Jenkins.ADMINISTER).everywhere().toAuthenticated());
        CredentialsProvider.lookupStores(r.jenkins).iterator().next().addCredentials(Domain.global(), new IdTokenStringCredentials(CredentialsScope.GLOBAL, "global", null));
        JSONObject config = r.getJSON("oidc/.well-known/openid-configuration").getJSONObject();
        System.err.println(config.toString(2));
        assertEquals(r.getURL() + "oidc", config.getString("issuer"));
        JenkinsRule.WebClient wc = r.createWebClient();
        Page p = wc.getPage(new URL(config.getString("jwks_uri")));
        assertEquals("application/json", p.getWebResponse().getContentType());
        JSONObject jwks = JSONObject.fromObject(p.getWebResponse().getContentAsString());
        System.err.println(jwks.toString(2));
        JSONArray keys = jwks.getJSONArray("keys");
        assertEquals(1, keys.size());
        JSONObject key = keys.getJSONObject(0);
        assertEquals("global", key.getString("kid"));
        assertEquals("RSA", key.getString("kty"));
        assertEquals("AQAB", key.getString("e"));
        assertEquals("RS256", key.getString("alg"));
        assertEquals("sig", key.getString("use"));
    }

}
