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

package io.jenkins.plugins.oidc_provider.config;

import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsStore;
import com.cloudbees.plugins.credentials.SystemCredentialsProvider;
import com.cloudbees.plugins.credentials.domains.Domain;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.ExtensionList;
import hudson.util.ListBoxModel;
import hudson.util.ListBoxModel.Option;
import io.jenkins.plugins.oidc_provider.IdTokenCredentials;
import io.jenkins.plugins.oidc_provider.IdTokenStringCredentials;
import io.jenkins.plugins.oidc_provider.Keys.SupportedKeyAlgorithm;
import io.jsonwebtoken.Claims;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import jenkins.model.GlobalConfiguration;
import jenkins.model.GlobalConfigurationCategory;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.StaplerRequest;

@Symbol("idToken")
@Extension public final class IdTokenConfiguration extends GlobalConfiguration {

    private static final List<ClaimTemplate> DEFAULT_CLAIM_TEMPLATES = Collections.emptyList();

    private static final List<ClaimTemplate> DEFAULT_BUILD_CLAIM_TEMPLATES = Collections.unmodifiableList(Arrays.asList(new ClaimTemplate[] {
        new ClaimTemplate(Claims.SUBJECT, "${JOB_URL}", new StringClaimType()),
        new ClaimTemplate("build_number", "${BUILD_NUMBER}", new IntegerClaimType())
    }));

    private static final List<ClaimTemplate> DEFAULT_GLOBAL_CLAIM_TEMPLATES = Collections.singletonList(
        new ClaimTemplate(Claims.SUBJECT, "${JENKINS_URL}", new StringClaimType()));

    private static final SupportedKeyAlgorithm DEFAULT_KEY_ALGORITHM = SupportedKeyAlgorithm.RS256;

    public static @NonNull IdTokenConfiguration get() {
        return ExtensionList.lookupSingleton(IdTokenConfiguration.class);
    }

    private int tokenLifetime = 3600;

    private @CheckForNull List<ClaimTemplate> claimTemplates;
    private @CheckForNull List<ClaimTemplate> buildClaimTemplates;
    private @CheckForNull List<ClaimTemplate> globalClaimTemplates;
    private SupportedKeyAlgorithm algorithm;

    public IdTokenConfiguration() {
        load();
    }

    @Override public GlobalConfigurationCategory getCategory() {
        return GlobalConfigurationCategory.get(GlobalConfigurationCategory.Security.class);
    }

    private static @CheckForNull List<ClaimTemplate> defaulted(@CheckForNull List<ClaimTemplate> claimTemplates, @NonNull List<ClaimTemplate> defaultClaimTemplates) {
        if (claimTemplates == null) {
            return null;
        }
        if (ClaimTemplate.xmlForm(claimTemplates).equals(ClaimTemplate.xmlForm(defaultClaimTemplates))) {
            return null;
        } else {
            return new ArrayList<>(claimTemplates);
        }
    }

    public int getTokenLifetime() {
        return tokenLifetime;
    }

    @DataBoundSetter public void setTokenLifetime(final int lifetime) {
        this.tokenLifetime = lifetime;
    }

    public @NonNull List<ClaimTemplate> getClaimTemplates() {
        return claimTemplates != null ? claimTemplates : DEFAULT_CLAIM_TEMPLATES;
    }

    @DataBoundSetter public void setClaimTemplates(@CheckForNull List<ClaimTemplate> claimTemplates) {
        this.claimTemplates = defaulted(claimTemplates, DEFAULT_CLAIM_TEMPLATES);
        save();
    }

    public @NonNull List<ClaimTemplate> getBuildClaimTemplates() {
        return buildClaimTemplates != null ? buildClaimTemplates : DEFAULT_BUILD_CLAIM_TEMPLATES;
    }

    @DataBoundSetter public void setBuildClaimTemplates(@CheckForNull List<ClaimTemplate> buildClaimTemplates) {
        this.buildClaimTemplates = defaulted(buildClaimTemplates, DEFAULT_BUILD_CLAIM_TEMPLATES);
        save();
    }

    public @NonNull List<ClaimTemplate> getGlobalClaimTemplates() {
        return globalClaimTemplates != null ? globalClaimTemplates : DEFAULT_GLOBAL_CLAIM_TEMPLATES;
    }

    @DataBoundSetter public void setGlobalClaimTemplates(@CheckForNull List<ClaimTemplate> globalClaimTemplates) {
        this.globalClaimTemplates = defaulted(globalClaimTemplates, DEFAULT_GLOBAL_CLAIM_TEMPLATES);
        save();
    }

    public @NonNull SupportedKeyAlgorithm getAlgorithm() {
        return algorithm != null ? algorithm : DEFAULT_KEY_ALGORITHM;
    }

    @DataBoundSetter public void setAlgorithm(SupportedKeyAlgorithm algorithm) {
        this.algorithm = algorithm;
        save();
    }

    public ListBoxModel doFillAlgorithmItems() {
        return new ListBoxModel(
            Arrays.stream(SupportedKeyAlgorithm.values())
                .map(a -> new Option(a.name()))
                .toArray(Option[]::new)
        );
    }

    @Override public boolean configure(StaplerRequest req, JSONObject json) throws FormException {
        // Allow empty lists to be configured (form binding will simply omit mention of them):
        claimTemplates = null;
        buildClaimTemplates = null;
        globalClaimTemplates = null;
        algorithm = null;

        boolean result =  super.configure(req, json);

        // TODO update all credentials once the algorithm has changed
        for (CredentialsStore store : CredentialsProvider.lookupStores(Jenkins.get())) {
            for (Domain domain : store.getDomains()) {
                for (Credentials credentials : store.getCredentials(domain)) {
                    if(!(credentials instanceof IdTokenCredentials)) {
                       continue;
                    }

                    try {
                        boolean updated = ((IdTokenCredentials) credentials).updateAlgorithm(algorithm);

                        if(updated) {
                            store.updateCredentials(domain, credentials, credentials);
                        }
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }
            }
        }

        return result;
    }

}
