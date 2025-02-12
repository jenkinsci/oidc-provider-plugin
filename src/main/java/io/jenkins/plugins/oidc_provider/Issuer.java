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
import com.cloudbees.plugins.credentials.CredentialsStore;
import com.cloudbees.plugins.credentials.domains.Domain;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.ExtensionPoint;
import hudson.model.Item;
import hudson.model.ItemGroup;
import hudson.model.ModelObject;
import hudson.model.Run;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;
import jenkins.model.Jenkins;
import org.kohsuke.stapler.StaplerRequest2;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;

/**
 * Representation of an issuer of tokens.
 */
public abstract class Issuer {

    private static final Logger LOGGER = Logger.getLogger(Issuer.class.getName());

    /**
     * The associated object in Jenkins.
     */
    protected abstract @NonNull ModelObject context();

    /**
     * Load credentials from this issuer.
     * Only credentials defined here will be returned—no inherited credentials,
     * unlike {@link CredentialsProvider#lookupStores}
     * or {@link CredentialsProvider#lookupCredentialsInItemGroup(Class, ItemGroup, Authentication, List)}.
     * @return a possibly empty set of credentials
     */
    public final @NonNull Collection<? extends IdTokenCredentials> credentials() {
        Map<String, IdTokenCredentials> credentials = new LinkedHashMap<>();
        for (CredentialsProvider p : CredentialsProvider.enabled(context())) {
            CredentialsStore store = p.getStore(context());
            if (store != null) {
                LOGGER.fine(() -> "found " + store + " for " + context());
                // TODO should we consider other domains?
                for (Credentials c : store.getCredentials(Domain.global())) {
                    if (c instanceof IdTokenCredentials) {
                        IdTokenCredentials itc = (IdTokenCredentials) c;
                        credentials.putIfAbsent(itc.getId(), itc);
                    }
                }
            }
        }
        LOGGER.fine(() -> "in " + context() + " found " + credentials.keySet());
        return credentials.values();
    }

    /**
     * URI suffix after {@code https://jenkins/oidc}.
     * Should match {@link Item#getUrl} or similar methods when applied to {@link #context},
     * except with an initial rather than a trailing slash ({@code /}).
     * @return the empty string, or e.g. {@code /path/subpath}
     * @see <a href="https://issues.jenkins.io/browse/JENKINS-26091">Marker interface for things with URL</a>
     */
    protected abstract @NonNull String uri();

    /**
     * Absolute URL of issuer.
     * @return e.g. {@code https://jenkins/oidc/path/subpath}
     */
    public final String url() {
        return Jenkins.get().getRootUrl() + Keys.URL_NAME + uri();
    }

    /**
     * Check permision on the {@link #context} to enumerate credentials and get their metadata.
     */
    protected abstract void checkExtendedReadPermission() throws AccessDeniedException;

    @Override public String toString() {
        return getClass().getSimpleName() + "[" + url() + "]";
    }

    public interface Factory extends ExtensionPoint {

        /**
         * Find an issuer by URI suffix.
         * @param uri a possible value of {@link #uri}
         * @return a corresponding issuer, if recognized
         */
        @CheckForNull Issuer forUri(@NonNull String uri);

        /**
         * Find issuers which might be applicable to a given build.
         * @param context a build context
         * @return issuers handled by this factory which might apply to this build, most specific first (possibly empty)
         */
        @NonNull Collection<? extends Issuer> forContext(@NonNull Run<?, ?> context);

        /**
         * Find an issuer potentially being configured from a certain screen.
         * @param req form validation request in a credentials configuration screen
         * @return a potential issuer for that location, if valid
         * @see StaplerRequest2#findAncestorObject
         */
        @CheckForNull Issuer forConfig(@NonNull StaplerRequest2 req);

    }

}
