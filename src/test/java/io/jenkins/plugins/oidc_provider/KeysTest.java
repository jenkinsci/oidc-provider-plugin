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

import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.CredentialsStore;
import com.cloudbees.plugins.credentials.SystemCredentialsProvider;
import com.cloudbees.plugins.credentials.domains.Domain;
import org.htmlunit.Page;
import hudson.ExtensionList;
import hudson.model.ItemGroup;
import hudson.model.ModelObject;
import hudson.security.Permission;
import java.io.IOException;
import java.net.URL;
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;
import jenkins.model.Jenkins;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.Assert.assertEquals;
import org.junit.Test;
import org.junit.Rule;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.LoggerRule;
import org.jvnet.hudson.test.MockAuthorizationStrategy;
import org.jvnet.hudson.test.TestExtension;

public class KeysTest {

    @Rule public JenkinsRule r = new JenkinsRule();
    @Rule public LoggerRule logging = new LoggerRule().recordPackage(Keys.class, Level.FINE);

    @Test public void globalEndpoint() throws Exception {
        r.jenkins.setSecurityRealm(r.createDummySecurityRealm());
        r.jenkins.setAuthorizationStrategy(new MockAuthorizationStrategy().grant(Jenkins.ADMINISTER).everywhere().toAuthenticated());
        CredentialsStore store = CredentialsProvider.lookupStores(r.jenkins).iterator().next();
        store.addCredentials(Domain.global(), new IdTokenStringCredentials(CredentialsScope.GLOBAL, "global", null, "TRUE"));
        IdTokenStringCredentials alt = new IdTokenStringCredentials(CredentialsScope.GLOBAL, "alt", null, "TRUE");
        alt.setIssuer("https://elsewhere");
        store.addCredentials(Domain.global(), alt);
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

    @Issue("https://github.com/jenkinsci/oidc-provider-plugin/issues/21")
    @Test public void extraCredentialsProvider() throws Exception {
        assertThat(ExtensionList.lookup(CredentialsProvider.class).get(0), instanceOf(ExtraProvider.class));
        SystemCredentialsProvider.getInstance().getDomainCredentialsMap().get(Domain.global()).add(new IdTokenStringCredentials(CredentialsScope.GLOBAL, "global", null, "TRUE"));
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
    }
    @SuppressWarnings({"deprecation", "rawtypes"})
    @TestExtension("extraCredentialsProvider") public static final class ExtraProvider extends CredentialsProvider {
        @Override public <C extends Credentials> List<C> getCredentials(Class<C> type, ItemGroup itemGroup,  org.acegisecurity.Authentication authentication) {
            return Collections.emptyList();
        }
        @Override public CredentialsStore getStore(ModelObject object) {
            return new CredentialsStore(ExtraProvider.class) {
                @Override public ModelObject getContext() {
                    return object;
                }
                @Override public boolean hasPermission(org.acegisecurity.Authentication a, Permission permission) {
                    return true;
                }
                @Override public List<Credentials> getCredentials(Domain domain) {
                    return Collections.emptyList();
                }
                @Override public boolean addCredentials(Domain domain, Credentials credentials) throws IOException {
                    throw new IOException("no");
                }
                @Override public boolean removeCredentials(Domain domain, Credentials credentials) throws IOException {
                    throw new IOException("no");
                }
                @Override public boolean updateCredentials(Domain domain, Credentials current, Credentials replacement) throws IOException {
                    throw new IOException("no");
                }
            };
        }
    }

}
