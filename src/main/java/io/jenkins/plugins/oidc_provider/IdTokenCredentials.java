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
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.ExtensionList;
import hudson.Util;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.util.FormValidation;
import hudson.util.Secret;
import io.jenkins.plugins.oidc_provider.config.ClaimTemplate;
import io.jenkins.plugins.oidc_provider.config.IdTokenConfiguration;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import java.util.logging.Logger;
import jenkins.model.Jenkins;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest2;

public abstract class IdTokenCredentials extends BaseStandardCredentials {

    private static final Logger LOGGER = Logger.getLogger(IdTokenCredentials.class.getName());

    private static final long serialVersionUID = 1;

    /**
     * Public/private RSA keypair.
     * {@link #privateKey} is the persistent form.
     */
    private transient KeyPair kp;

    /**
     * Encrypted {@link Base64} encoding of RSA private key in {@link RSAPrivateCrtKey} / {@link PKCS8EncodedKeySpec} format.
     * The public key is inferred from this to reload {@link #kp}.
     */
    private final Secret privateKey;

    private @CheckForNull String issuer;

    private @CheckForNull String audience;

    private transient @CheckForNull Run<?, ?> build;

    protected IdTokenCredentials(CredentialsScope scope, String id, String description) {
        this(scope, id, description, generatePrivateKey());
    }

    private static KeyPair generatePrivateKey() {
        KeyPairGenerator gen;
        try {
            gen = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException x) {
            throw new AssertionError(x);
        }
        gen.initialize(2048);
        return gen.generateKeyPair();
    }

    private IdTokenCredentials(CredentialsScope scope, String id, String description, KeyPair kp) {
        this(scope, id, description, kp, serializePrivateKey(kp));
    }

    private static Secret serializePrivateKey(KeyPair kp) {
        assert ((RSAPublicKey) kp.getPublic()).getModulus().equals(((RSAPrivateCrtKey) kp.getPrivate()).getModulus());
        return Secret.fromString(Base64.getEncoder().encodeToString(kp.getPrivate().getEncoded()));
    }

    protected IdTokenCredentials(CredentialsScope scope, String id, String description, KeyPair kp, Secret privateKey) {
        super(scope, id, description);
        this.kp = kp;
        this.privateKey = privateKey;
    }

    protected Object readResolve() throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPrivateCrtKey priv = (RSAPrivateCrtKey) kf.generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKey.getPlainText())));
        kp = new KeyPair(kf.generatePublic(new RSAPublicKeySpec(priv.getModulus(), priv.getPublicExponent())), priv);
        return this;
    }

    public final String getIssuer() {
        return issuer;
    }

    @DataBoundSetter public final void setIssuer(String issuer) {
        this.issuer = Util.fixEmpty(issuer);
    }

    public final String getAudience() {
        return audience;
    }

    @DataBoundSetter public final void setAudience(String audience) {
        this.audience = Util.fixEmpty(audience);
    }

    protected abstract IdTokenCredentials clone(KeyPair kp, Secret privateKey);

    @Override public final Credentials forRun(Run<?, ?> context) {
        IdTokenCredentials clone = clone(kp, privateKey);
        clone.issuer = issuer;
        clone.audience = audience;
        clone.build = context;
        return clone;
    }

    RSAPublicKey publicKey() {
        return (RSAPublicKey) kp.getPublic();
    }

    /**
     * Claims that must not be defined by user claim templates, because they have special meanings.
     * {@code sub} is treated specially: it <em>must</em> be defined by a claim template.
     * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">OpenID Connect list</a>
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1">JWT list</a>
     */
    public static final Set<String> STANDARD_CLAIMS = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
        Claims.ISSUER,
        Claims.AUDIENCE,
        Claims.EXPIRATION,
        Claims.ISSUED_AT,
        "auth_time",
        "nonce",
        "acr",
        "amr",
        "azp",
        Claims.NOT_BEFORE,
        Claims.ID
    )));

    protected final @NonNull String token() {
        IdTokenConfiguration cfg = IdTokenConfiguration.get();
        JwtBuilder builder = Jwts.builder().
            setHeaderParam("kid", getId()).
            setIssuer(issuer != null ? issuer : findIssuer().url()).
            setAudience(audience).
            setExpiration(Date.from(Instant.now().plus(cfg.getTokenLifetime(), ChronoUnit.SECONDS))).
            setIssuedAt(new Date());
        Map<String, String> env;
        if (build != null) {
            try {
                env = build.getEnvironment(TaskListener.NULL);
            } catch (IOException | InterruptedException x) {
                throw new RuntimeException(x);
            }
        } else {
            // EnvVars.masterEnvVars might not be safe to expose
            env = Collections.singletonMap("JENKINS_URL", Jenkins.get().getRootUrl());
        }
        AtomicBoolean definedSub = new AtomicBoolean();
        Map<String, Boolean> definedClaims = new HashMap<>();
        Consumer<List<ClaimTemplate>> addClaims = claimTemplates -> {
            for (ClaimTemplate t : claimTemplates) {
                if (STANDARD_CLAIMS.contains(t.name)) {
                    throw new SecurityException("An id token claim template must not specify " + t.name);
                } else if (t.name.equals(Claims.SUBJECT)) {
                    definedSub.set(true);
                }
                if (t.getRequiredEnvVars() == null || env.keySet().containsAll(Arrays.asList(t.getRequiredEnvVars().split("\\s*\\s")))) {
                    if (definedClaims.containsKey(t.name)) {
                        LOGGER.fine(() -> "declining to set claim: " + t.name + " with format: " + t.format + " as it has already been set.");
                    } else {
                        LOGGER.fine(() -> "setting claim: " + t.name + " with format: " + t.format);
                        builder.claim(t.name, t.type.parse(Util.replaceMacro(t.format, env)));
                        definedClaims.put(t.name, true);
                    }
                }
            }
        };
        LOGGER.fine("setting claim templates");
        addClaims.accept(cfg.getClaimTemplates());
        if (build != null) {
            LOGGER.fine("setting build claim templates");
            addClaims.accept(cfg.getBuildClaimTemplates());
        } else {
            LOGGER.fine("setting global claim templates");
            addClaims.accept(cfg.getGlobalClaimTemplates());
        }
        if (!definedSub.get()) {
            throw new SecurityException("An id token claim template must specify " + Claims.SUBJECT);
        }
        return builder.
            signWith(kp.getPrivate()).
            compact();
    }

    protected @NonNull Issuer findIssuer() {
        Run<?, ?> context = build;
        if (context == null) {
            return ExtensionList.lookupSingleton(RootIssuer.class);
        } else {
            for (Issuer.Factory f : ExtensionList.lookup(Issuer.Factory.class)) {
                for (Issuer i : f.forContext(context)) {
                    if (i.credentials().contains(this)) {
                        return i;
                    }
                }
            }
        }
        throw new IllegalStateException("Could not find issuer corresponding to " + getId() + " for " + context.getExternalizableId());
    }

    protected static abstract class IdTokenCredentialsDescriptor extends BaseStandardCredentialsDescriptor {

        private static @CheckForNull Issuer issuerFromRequest(@NonNull StaplerRequest2 req) {
            Issuer i = ExtensionList.lookup(Issuer.Factory.class).stream().map(f -> f.forConfig(req)).filter(Objects::nonNull).findFirst().orElse(null);
            if (i != null) {
                i.checkExtendedReadPermission();
            }
            return i;
        }

        public final FormValidation doCheckIssuer(StaplerRequest2 req, @QueryParameter String id, @QueryParameter String issuer) {
            Issuer i = issuerFromRequest(req);
            if (Util.fixEmpty(issuer) == null) {
                if (i != null) {
                    return FormValidation.okWithMarkup("Issuer URI: <code>" + Util.escape(i.url()) + "</code>");
                } else {
                    return FormValidation.warning("Unable to determine the issuer URI");
                }
            } else {
                try {
                    URI u = new URI(issuer);
                    if (!"https".equals(u.getScheme())) {
                        return FormValidation.errorWithMarkup("Issuer URIs should use <code>https</code> scheme");
                    }
                    if (u.getQuery() != null) {
                        return FormValidation.error("Issuer URIs must not have a query component");
                    }
                    if (u.getFragment() != null) {
                        return FormValidation.error("Issuer URIs must not have a fragment component");
                    }
                    if (u.getPath() != null && u.getPath().endsWith("/")) {
                        return FormValidation.errorWithMarkup("Issuer URIs should not end with a slash (<code>/</code>) in this context");
                    }
                } catch (URISyntaxException x) {
                    return FormValidation.error("Not a well-formed URI");
                }
                if (i != null) {
                    IdTokenCredentials c = i.credentials().stream().filter(creds -> creds.getId().equals(id) && issuer.equals(creds.getIssuer())).findFirst().orElse(null);
                    if (c != null) {
                        String base = req.getRequestURI().replaceFirst("/checkIssuer$", "");
                        return FormValidation.okWithMarkup(
                            "Serve <code>" + Util.xmlEscape(issuer) + Keys.WELL_KNOWN_OPENID_CONFIGURATION +
                            "</code> with <a href=\"" + base + "/wellKnownOpenidConfiguration?issuer=" + Util.escape(issuer) +
                            "\" target=\"_blank\" rel=\"noopener noreferrer\">this content</a> and <code>" +
                            Util.xmlEscape(issuer) + Keys.JWKS + "</code> with <a href=\"" +
                            base + "/jwks?id=" + Util.escape(id) + "&issuer=" + Util.escape(issuer) +
                            "\" target=\"_blank\" rel=\"noopener noreferrer\">this content</a> (both as <code>application/json</code>)." +
                            "<br>Note that the JWKS document will need to be updated if you resave these credentials.");
                    } else {
                        return FormValidation.ok("Save these credentials, then return to this screen for instructions");
                    }
                } else {
                    return FormValidation.warning("Unable to determine where these credentials are being saved");
                }
            }
        }

        public JSONObject doWellKnownOpenidConfiguration(@QueryParameter String issuer) {
            return Keys.openidConfiguration(issuer);
        }

        public JSONObject doJwks(StaplerRequest2 req, @QueryParameter String id, @QueryParameter String issuer) {
            Issuer i = issuerFromRequest(req);
            if (i == null) {
                throw HttpResponses.notFound();
            }
            IdTokenCredentials c = i.credentials().stream().filter(creds -> creds.getId().equals(id) && issuer.equals(creds.getIssuer())).findFirst().orElse(null);
            if (c == null) {
                throw HttpResponses.notFound();
            }
            return new JSONObject().accumulate("keys", new JSONArray().element(Keys.key(c)));
        }

    }

}
