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
import hudson.util.Secret;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import jenkins.model.Jenkins;
import org.kohsuke.stapler.DataBoundSetter;

public abstract class IdTokenCredentials extends BaseStandardCredentials {

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

    public final String getAudience() {
        return audience;
    }

    @DataBoundSetter public final void setAudience(String audience) {
        this.audience = Util.fixEmpty(audience);
    }

    protected abstract IdTokenCredentials clone(KeyPair kp, Secret privateKey);

    @Override public final Credentials forRun(Run<?, ?> context) {
        IdTokenCredentials clone = clone(kp, privateKey);
        clone.audience = audience;
        clone.build = context;
        return clone;
    }

    RSAPublicKey publicKey() {
        return (RSAPublicKey) kp.getPublic();
    }

    protected final @NonNull String token() {
        JwtBuilder builder = Jwts.builder().
            setHeaderParam("kid", getId()).
            setIssuer(findIssuer().url()).
            setAudience(audience).
            setExpiration(Date.from(new Date().toInstant().plus(1, ChronoUnit.HOURS))).
            setIssuedAt(new Date());
        if (build != null) {
            builder.setSubject(build.getParent().getAbsoluteUrl()).
                claim("build_number", build.getNumber());
        } else {
            builder.setSubject(Jenkins.get().getRootUrl());
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

}
