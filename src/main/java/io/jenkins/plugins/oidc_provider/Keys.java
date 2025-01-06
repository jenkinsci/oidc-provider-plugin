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

import edu.umd.cs.findbugs.annotations.CheckForNull;
import hudson.Extension;
import hudson.ExtensionList;
import hudson.model.InvisibleAction;
import hudson.model.UnprotectedRootAction;
import hudson.security.ACL;
import hudson.security.ACLContext;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.logging.Logger;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.StaplerRequest;

/**
 * Serves OIDC definition and JWKS.
 * @see <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig">Obtaining OpenID Provider Configuration Information</a>
 * @see <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata">OpenID Provider Metadata</a>
 */
@Extension public final class Keys extends InvisibleAction implements UnprotectedRootAction {

    private static final Logger LOGGER = Logger.getLogger(Keys.class.getName());

    static final String URL_NAME = "oidc";
    static final String WELL_KNOWN_OPENID_CONFIGURATION = "/.well-known/openid-configuration";
    static final String JWKS = "/jwks";

    @Override public String getUrlName() {
        return URL_NAME;
    }

    public JSONObject doDynamic(StaplerRequest req) {
        String path = req.getOriginalRestOfPath();
        try (ACLContext context = ACL.as2(ACL.SYSTEM2)) { // both forUri and credentials might check permissions
            Issuer i = findIssuer(path, WELL_KNOWN_OPENID_CONFIGURATION);
            if (i != null) {
                return openidConfiguration(i.url());
            } else {
                i = findIssuer(path, JWKS);
                if (i != null) {
                    // pending https://github.com/jwtk/jjwt/issues/236
                    // compare https://github.com/jenkinsci/blueocean-plugin/blob/1f92e1624287e7588fc89aa5ce4e4147dd00f3d7/blueocean-jwt/src/main/java/io/jenkins/blueocean/auth/jwt/SigningPublicKey.java#L45-L52
                    JSONArray keys = new JSONArray();
                    for (IdTokenCredentials creds : i.credentials()) {
                        if (creds.getIssuer() != null) {
                            LOGGER.fine(() -> "declining to serve key for " + creds.getId() + " since it would be served from " + creds.getIssuer());
                            continue;
                        }
                        keys.element(key(creds));
                    }
                    return new JSONObject().accumulate("keys", keys);
                }
            }
            throw HttpResponses.notFound();
        }
    }

    static JSONObject openidConfiguration(String issuer) {
        return new JSONObject().
            accumulate("issuer", issuer).
            accumulate("jwks_uri", issuer + JWKS).
            accumulate("response_types_supported", new JSONArray().element("code")).
            accumulate("subject_types_supported", new JSONArray().element("public")).
            accumulate("id_token_signing_alg_values_supported", new JSONArray().element("RS256")).
            accumulate("authorization_endpoint", "https://unimplemented").
            accumulate("token_endpoint", "https://unimplemented");
    }

    static JSONObject key(IdTokenCredentials creds) {
        RSAPublicKey key = creds.publicKey();
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        return new JSONObject().
            accumulate("kid", creds.getId()).
            accumulate("kty", "RSA").
            accumulate("alg", "RS256").
            accumulate("use", "sig").
            accumulate("n", encoder.encodeToString(key.getModulus().toByteArray())).
            accumulate("e", encoder.encodeToString(key.getPublicExponent().toByteArray()));
    }

    /**
     * @param path e.g. {@code /path/subpath/jwks}
     * @param suffix e.g. {@code /jwks}
     */
    private static @CheckForNull Issuer findIssuer(String path, String suffix) {
        if (path.endsWith(suffix)) {
            String uri = path.substring(0, path.length() - suffix.length()); // e.g. "" or "/path/subpath"
            LOGGER.fine(() -> "looking up issuer for " + uri);
            for (Issuer.Factory f : ExtensionList.lookup(Issuer.Factory.class)) {
                Issuer i = f.forUri(uri);
                if (i != null) {
                    if (!i.uri().equals(uri)) {
                        LOGGER.warning(() -> i + " was expected to have URI " + uri);
                        return null;
                    }
                    if (i.credentials().stream().noneMatch(c -> c.getIssuer() == null)) {
                        LOGGER.fine(() -> "found " + i + " but has no credentials with default issuer; not advertising existence of a folder");
                        return null;
                    }
                    LOGGER.fine(() -> "found " + i);
                    return i;
                }
            }
        }
        return null;
    }

}
