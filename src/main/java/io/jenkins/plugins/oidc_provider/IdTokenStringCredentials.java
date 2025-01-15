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

import com.cloudbees.plugins.credentials.CredentialsScope;
import hudson.Extension;
import hudson.util.Secret;
import io.jenkins.plugins.oidc_provider.Keys.SupportedKeyAlgorithm;
import java.security.KeyPair;
import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.plaincredentials.StringCredentials;
import org.kohsuke.stapler.DataBoundConstructor;

/**
 * Supplies an id token to a build.
 */
public final class IdTokenStringCredentials extends IdTokenCredentials implements StringCredentials {

    private static final long serialVersionUID = 1;

    public IdTokenStringCredentials(CredentialsScope scope, String id, String description, SupportedKeyAlgorithm algorithm) {
        super(scope, id, description, algorithm);
    }

    @DataBoundConstructor public IdTokenStringCredentials(CredentialsScope scope, String id, String description) {
        super(scope, id, description);
    }

    private IdTokenStringCredentials(CredentialsScope scope, String id, String description, KeyPair kp,  SupportedKeyAlgorithm algorithm, SecretKeyPair secretKeyPair) {
        super(scope, id, description, kp,  algorithm, secretKeyPair);
    }

    @Override public Secret getSecret() {
        return Secret.fromString(token());
    }

    @Override protected IdTokenCredentials clone(KeyPair kp, SupportedKeyAlgorithm algorithm, SecretKeyPair secretKeyPair) {
        return new IdTokenStringCredentials(getScope(), getId(), getDescription(), kp, algorithm, secretKeyPair);
    }

    @Symbol("idToken")
    @Extension public static class DescriptorImpl extends IdTokenCredentialsDescriptor {

        @Override public String getDisplayName() {
            return "OpenID Connect id token";
        }

    }

}
