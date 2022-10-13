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

import com.cloudbees.hudson.plugins.folder.Folder;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.domains.Domain;
import com.gargoylesoftware.htmlunit.html.HtmlAnchor;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import hudson.model.Result;
import java.math.BigInteger;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import jenkins.model.Jenkins;
import org.junit.Test;
import static org.hamcrest.Matchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;
import org.junit.Rule;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.JenkinsSessionRule;
import org.jvnet.hudson.test.MockAuthorizationStrategy;

public class IdTokenCredentialsTest {

    @Rule public JenkinsSessionRule rr = new JenkinsSessionRule();

    @Test public void persistence() throws Throwable {
        AtomicReference<BigInteger> modulus = new AtomicReference<>();
        rr.then(r -> {
            IdTokenStringCredentials c = new IdTokenStringCredentials(CredentialsScope.GLOBAL, "test", null);
            c.setIssuer("https://issuer");
            c.setAudience("https://audience");
            CredentialsProvider.lookupStores(r.jenkins).iterator().next().addCredentials(Domain.global(), c);
            modulus.set(c.publicKey().getModulus());
        });
        rr.then(r -> {
            List<IdTokenStringCredentials> creds = CredentialsProvider.lookupCredentials(IdTokenStringCredentials.class, r.jenkins, null, Collections.emptyList());
            assertThat(creds, hasSize(1));
            assertThat(creds.get(0).getId(), is("test"));
            assertThat(creds.get(0).getIssuer(), is("https://issuer"));
            assertThat(creds.get(0).getAudience(), is("https://audience"));
            assertThat("private key retained by serialization", creds.get(0).publicKey().getModulus(), is(modulus.get()));
            HtmlForm form = r.createWebClient().goTo("credentials/store/system/domain/_/credential/test/update").getFormByName("update");
            form.getInputByName("_.description").setValueAttribute("my creds");
            r.submit(form);
            creds = CredentialsProvider.lookupCredentials(IdTokenStringCredentials.class, r.jenkins, null, Collections.emptyList());
            assertThat(creds, hasSize(1));
            assertThat(creds.get(0).getDescription(), is("my creds"));
            assertThat("private key rotated by resaving", creds.get(0).publicKey().getModulus(), is(not(modulus.get())));
            creds.get(0).setIssuer(null);
            creds.get(0).setAudience(null);
            r.submit(r.createWebClient().goTo("credentials/store/system/domain/_/credential/test/update").getFormByName("update"));
            creds = CredentialsProvider.lookupCredentials(IdTokenStringCredentials.class, r.jenkins, null, Collections.emptyList());
            assertThat(creds, hasSize(1));
            assertThat(creds.get(0).getIssuer(), is(nullValue()));
            assertThat(creds.get(0).getAudience(), is(nullValue()));
        });
    }

    @Test public void checkIssuer() throws Throwable {
        rr.then(r -> {
            IdTokenStringCredentials c = new IdTokenStringCredentials(CredentialsScope.GLOBAL, "ext1", null);
            c.setIssuer("https://xxx");
            CredentialsProvider.lookupStores(r.jenkins).iterator().next().addCredentials(Domain.global(), c);
            Folder dir = r.createProject(Folder.class, "dir");
            c = new IdTokenStringCredentials(CredentialsScope.GLOBAL, "ext2", null);
            c.setIssuer("https://xxx");
            CredentialsProvider.lookupStores(dir).iterator().next().addCredentials(Domain.global(), c);
            r.jenkins.setSecurityRealm(r.createDummySecurityRealm());
            r.jenkins.setAuthorizationStrategy(new MockAuthorizationStrategy().grant(Jenkins.ADMINISTER).everywhere().toAuthenticated());
            JenkinsRule.WebClient wc = r.createWebClient();
            String descriptorUrl = "descriptorByName/" + IdTokenStringCredentials.class.getName() + "/";
            String folderDescriptorUrl = "job/dir/" + descriptorUrl;
            wc.assertFails(descriptorUrl + "checkIssuer?id=ext1&issuer=", 403);
            wc.assertFails(folderDescriptorUrl + "checkIssuer?id=ext2&issuer=", 403);
            wc.assertFails(descriptorUrl + "jwks?id=ext1&issuer=", 403);
            wc.assertFails(folderDescriptorUrl + "jwks?id=ext2&issuer=", 403);
            wc.login("admin");
            assertThat(wc.goTo(descriptorUrl + "checkIssuer?id=ext1&issuer=").getWebResponse().getContentAsString(), containsString("/jenkins/oidc"));
            assertThat(wc.goTo(folderDescriptorUrl + "checkIssuer?id=ext2&issuer=").getWebResponse().getContentAsString(), containsString("/jenkins/oidc/job/dir"));
            assertThat(wc.goTo(descriptorUrl + "checkIssuer?id=ext1&issuer=https://xxx").getWebResponse().getContentAsString(), containsString("https://xxx/jwks"));
            HtmlPage message = wc.goTo(folderDescriptorUrl + "checkIssuer?id=ext2&issuer=https://xxx");
            String messageText = message.getWebResponse().getContentAsString();
            System.out.println(messageText);
            assertThat(messageText, containsString("https://xxx/jwks"));
            for (HtmlAnchor anchor : message.getAnchors()) {
                wc.getPage(message.getFullyQualifiedUrl(anchor.getHrefAttribute()));
            }
            assertThat(wc.goTo(descriptorUrl + "wellKnownOpenidConfiguration?issuer=https://xxx", "application/json").getWebResponse().getContentAsString(), containsString("\"jwks_uri\":\"https://xxx/jwks\""));
            assertThat(wc.goTo(folderDescriptorUrl + "wellKnownOpenidConfiguration?issuer=https://xxx", "application/json").getWebResponse().getContentAsString(), containsString("\"jwks_uri\":\"https://xxx/jwks\""));
            assertThat(wc.goTo(descriptorUrl + "jwks?id=ext1&issuer=https://xxx", "application/json").getWebResponse().getContentAsString(), containsString("\"kid\":\"ext1\""));
            assertThat(wc.goTo(folderDescriptorUrl + "jwks?id=ext2&issuer=https://xxx", "application/json").getWebResponse().getContentAsString(), containsString("\"kid\":\"ext2\""));
        });
    }

    @Test public void invalidCustomClaims() throws Throwable {
        rr.then(r -> {
            CredentialsProvider.lookupStores(r.jenkins).iterator().next().addCredentials(Domain.global(), new IdTokenStringCredentials(CredentialsScope.GLOBAL, "test", null));
            WorkflowJob p = r.createProject(WorkflowJob.class, "p");
            p.setDefinition(new CpsFlowDefinition("withCredentials([string(variable: 'TOK', credentialsId: 'test')]) {echo(/should not get $TOK/)}", true));
            IdTokenConfiguration cfg = IdTokenConfiguration.get();
            cfg.setClaimTemplates(Collections.singletonList(new IdTokenConfiguration.ClaimTemplate("iss", "oops must not be overridden", IdTokenConfiguration.ClaimType.STRING)));
            r.assertLogContains("must not specify iss", r.buildAndAssertStatus(Result.FAILURE, p));
            cfg.setClaimTemplates(Collections.emptyList());
            cfg.setBuildClaimTemplates(Collections.singletonList(new IdTokenConfiguration.ClaimTemplate("stuff", "fine but where is sub?", IdTokenConfiguration.ClaimType.STRING)));
            r.assertLogContains("must specify sub", r.buildAndAssertStatus(Result.FAILURE, p));
        });
    }

}
