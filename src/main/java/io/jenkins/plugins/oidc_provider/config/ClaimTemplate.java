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

import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.Util;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import hudson.util.FormValidation;
import io.jenkins.plugins.oidc_provider.IdTokenCredentials;
import java.util.List;
import java.util.stream.Collectors;
import jenkins.model.Jenkins;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;

public final class ClaimTemplate extends AbstractDescribableImpl<ClaimTemplate> {

    public final @NonNull String name;
    public final @NonNull String format;
    public final @NonNull ClaimType type;
    private @CheckForNull String requiredEnvVars;

    @DataBoundConstructor public ClaimTemplate(String name, String format, ClaimType type) {
        this.name = name;
        this.format = format;
        this.type = type;
    }

    @DataBoundSetter
    public void setRequiredEnvVars(String vars) {
        this.requiredEnvVars = Util.fixEmpty(vars);
    }

    public String getRequiredEnvVars() {
        return this.requiredEnvVars;
    }

    @Restricted(NoExternalUse.class)
    public String xmlForm() {
        return Jenkins.XSTREAM2.toXML(this);
    }

    @Restricted(NoExternalUse.class)
    public static List<String> xmlForm(List<ClaimTemplate> claimTemplates) {
        return claimTemplates.stream().map(ct -> Jenkins.XSTREAM2.toXML(ct)).collect(Collectors.toList());
    }

    @Extension public static final class DescriptorImpl extends Descriptor<ClaimTemplate> {

        public ClaimType getDefaultType() {
            return new StringClaimType();
        }

        public FormValidation doCheckName(@QueryParameter String value) {
            if (Util.fixEmpty(value) == null) {
                return FormValidation.error("You must specify a claim name.");
            } else if (IdTokenCredentials.STANDARD_CLAIMS.contains(value)) {
                return FormValidation.error("You must not specify this standard claim.");
            } else {
                return FormValidation.ok();
            }
        }

        public FormValidation doCheckRequiredEnvVars(@QueryParameter String value) {
            if (!value.equals(value.toUpperCase())) {
                return FormValidation.warning("Defined environment variables should be in upper case.");
            } else {
                return FormValidation.ok();
            }
        }

    }

}
