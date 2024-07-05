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

import hudson.Extension;
import hudson.model.Item;
import hudson.model.ModelObject;
import hudson.model.Run;
import java.util.Collection;
import java.util.Collections;
import jenkins.model.Jenkins;
import org.kohsuke.stapler.StaplerRequest;
import org.springframework.security.access.AccessDeniedException;

/**
 * Issuer scoped to Jenkins root with global credentials.
 */
@Extension public final class RootIssuer extends Issuer implements Issuer.Factory {

    @Override public Issuer forUri(String prefix) {
        return prefix.isEmpty() ? this : null;
    }

    @Override protected ModelObject context() {
        return Jenkins.get();
    }

    @Override protected String uri() {
        return "";
    }

    @Override protected void checkExtendedReadPermission() throws AccessDeniedException {
        Jenkins.get().checkPermission(Jenkins.MANAGE);
    }

    @Override public Collection<? extends Issuer> forContext(Run<?, ?> context) {
        return Collections.singleton(this);
    }

    @Override public Issuer forConfig(StaplerRequest req) {
        // TODO or unconditionally return this, but register at a lower number than FolderIssuer?
        return req.findAncestorObject(Item.class) == null ? this : null;
    }

}
