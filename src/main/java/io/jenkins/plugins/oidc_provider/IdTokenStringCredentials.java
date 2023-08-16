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
import hudson.model.ModelObject;
import hudson.util.Secret;
import jenkins.model.Jenkins;

import java.security.KeyPair;
import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.plaincredentials.StringCredentials;
import org.kohsuke.stapler.DataBoundConstructor;

/**
 * Supplies an id token to a build.
 */
public final class IdTokenStringCredentials extends IdTokenCredentials implements StringCredentials {

    private static final long serialVersionUID = 1;

    @DataBoundConstructor public IdTokenStringCredentials(CredentialsScope scope, String id, String description, String rotate) {
        super(scope, id, description, rotate);
    }

    private IdTokenStringCredentials(CredentialsScope scope, String id, String description, KeyPair kp, Secret privateKey, String rotate) {
        super(scope, id, description, kp, privateKey, rotate);
    }

    @Override public Secret getSecret() {
        return Secret.fromString(token());
    }

    @Override protected IdTokenCredentials clone(KeyPair kp, Secret privateKey) {
        return new IdTokenStringCredentials(getScope(), getId(), getDescription(), kp, privateKey, "TRUE");
    }

    @Symbol("idToken")
    @Extension public static class DescriptorImpl extends IdTokenCredentialsDescriptor {

        @Override public String getDisplayName() {
            return "OpenID Connect id token";
        }

    }

    @Override protected ModelObject context() {
        return Jenkins.get();
    }
}
