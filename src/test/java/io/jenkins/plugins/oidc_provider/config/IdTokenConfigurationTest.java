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

import java.util.Arrays;
import java.util.Collections;
import static org.junit.Assert.assertEquals;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsSessionRule;

public class IdTokenConfigurationTest {

    @Rule public JenkinsSessionRule rr = new JenkinsSessionRule();

    @Test public void gui() throws Throwable {
        rr.then(r -> {
            IdTokenConfiguration cfg = IdTokenConfiguration.get();
            cfg.setClaimTemplates(Collections.singletonList(new ClaimTemplate("ok", "true", new BooleanClaimType())));
            cfg.setGlobalClaimTemplates(Collections.singletonList(new ClaimTemplate("sub", "jenkins", new StringClaimType())));
            cfg.setBuildClaimTemplates(Arrays.asList(new ClaimTemplate("sub", "${JOB_NAME}", new StringClaimType()), new ClaimTemplate("num", "${BUILD_NUMBER}", new IntegerClaimType())));
            r.submit(r.createWebClient().goTo("configureSecurity").getFormByName("config"));
            assertEquals(ClaimTemplate.xmlForm(Collections.singletonList(new ClaimTemplate("ok", "true", new BooleanClaimType()))),
                ClaimTemplate.xmlForm(cfg.getClaimTemplates()));
            assertEquals(ClaimTemplate.xmlForm(Collections.singletonList(new ClaimTemplate("sub", "jenkins", new StringClaimType()))),
                ClaimTemplate.xmlForm(cfg.getGlobalClaimTemplates()));
            assertEquals(ClaimTemplate.xmlForm(Arrays.asList(new ClaimTemplate("sub", "${JOB_NAME}", new StringClaimType()), new ClaimTemplate("num", "${BUILD_NUMBER}", new IntegerClaimType()))),
                ClaimTemplate.xmlForm(cfg.getBuildClaimTemplates()));
        });
        rr.then(r -> {
            IdTokenConfiguration cfg = IdTokenConfiguration.get();
            assertEquals(ClaimTemplate.xmlForm(Collections.singletonList(new ClaimTemplate("ok", "true", new BooleanClaimType()))),
                ClaimTemplate.xmlForm(cfg.getClaimTemplates()));
            assertEquals(ClaimTemplate.xmlForm(Collections.singletonList(new ClaimTemplate("sub", "jenkins", new StringClaimType()))),
                ClaimTemplate.xmlForm(cfg.getGlobalClaimTemplates()));
            assertEquals(ClaimTemplate.xmlForm(Arrays.asList(new ClaimTemplate("sub", "${JOB_NAME}", new StringClaimType()), new ClaimTemplate("num", "${BUILD_NUMBER}", new IntegerClaimType()))),
                ClaimTemplate.xmlForm(cfg.getBuildClaimTemplates()));
            cfg.setClaimTemplates(Collections.emptyList());
            r.submit(r.createWebClient().goTo("configureSecurity").getFormByName("config"));
            assertEquals(ClaimTemplate.xmlForm(Collections.emptyList()),
                ClaimTemplate.xmlForm(cfg.getClaimTemplates()));
            assertEquals(ClaimTemplate.xmlForm(Collections.singletonList(new ClaimTemplate("sub", "jenkins", new StringClaimType()))),
                ClaimTemplate.xmlForm(cfg.getGlobalClaimTemplates()));
            assertEquals(ClaimTemplate.xmlForm(Arrays.asList(new ClaimTemplate("sub", "${JOB_NAME}", new StringClaimType()), new ClaimTemplate("num", "${BUILD_NUMBER}", new IntegerClaimType()))),
                ClaimTemplate.xmlForm(cfg.getBuildClaimTemplates()));
        });
    }

}
