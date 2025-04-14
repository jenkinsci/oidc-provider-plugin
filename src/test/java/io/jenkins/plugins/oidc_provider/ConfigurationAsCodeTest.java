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

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import io.jenkins.plugins.casc.misc.ConfiguredWithCode;
import io.jenkins.plugins.casc.misc.JenkinsConfiguredWithCodeRule;
import io.jenkins.plugins.oidc_provider.config.BooleanClaimType;
import io.jenkins.plugins.oidc_provider.config.ClaimTemplate;
import io.jenkins.plugins.oidc_provider.config.IdTokenConfiguration;
import io.jenkins.plugins.oidc_provider.config.IntegerClaimType;
import io.jenkins.plugins.oidc_provider.config.StringClaimType;
import java.util.Arrays;
import java.util.Collections;
import org.junit.Test;
import static org.hamcrest.Matchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertEquals;
import org.junit.Rule;

public class ConfigurationAsCodeTest {

    @Rule public JenkinsConfiguredWithCodeRule r = new JenkinsConfiguredWithCodeRule();

    @ConfiguredWithCode("jcasc.yaml")
    @Test public void basics() throws Exception {
        IdTokenStringCredentials c1 = CredentialsProvider.lookupCredentialsInItemGroup(IdTokenStringCredentials.class, r.jenkins, null, Collections.emptyList()).get(0);
        assertThat(c1.getId(), is("my-jwt-1"));
        assertThat(c1.getScope(), is(CredentialsScope.GLOBAL));
        assertThat(c1.getAudience(), is("wherever.net"));
        IdTokenFileCredentials c2 = CredentialsProvider.lookupCredentialsInItemGroup(IdTokenFileCredentials.class, r.jenkins, null, Collections.emptyList()).get(0);
        assertThat(c2.getId(), is("my-jwt-2"));
        assertThat(c2.getAudience(), is(nullValue()));
    }

    @ConfiguredWithCode("global.yaml")
    @Test public void globalConfiguration() throws Exception {
        IdTokenConfiguration cfg = IdTokenConfiguration.get();
        assertEquals(60, cfg.getTokenLifetime());
        assertEquals(ClaimTemplate.xmlForm(Collections.singletonList(new ClaimTemplate("ok", "true", new BooleanClaimType()))),
            ClaimTemplate.xmlForm(cfg.getClaimTemplates()));
        assertEquals(ClaimTemplate.xmlForm(Collections.singletonList(new ClaimTemplate("sub", "jenkins", new StringClaimType()))),
            ClaimTemplate.xmlForm(cfg.getGlobalClaimTemplates()));
        ClaimTemplate claimWithRequired = new ClaimTemplate("sub", "${JOB_NAME}", new StringClaimType());
        claimWithRequired.setRequiredEnvVars("JOB_NAME");
        assertEquals(ClaimTemplate.xmlForm(Arrays.asList(claimWithRequired, new ClaimTemplate("num", "${BUILD_NUMBER}", new IntegerClaimType()))),
            ClaimTemplate.xmlForm(cfg.getBuildClaimTemplates()));
    }

}
