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

import edu.umd.cs.findbugs.annotations.NonNull;
import io.jenkins.plugins.oidc_provider.config.IdTokenConfiguration;
import io.jenkins.plugins.oidc_provider.config.ClaimTemplate;
import com.cloudbees.hudson.plugins.folder.Folder;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.domains.Domain;
import hudson.EnvVars;
import hudson.model.EnvironmentContributor;
import hudson.model.Job;
import org.htmlunit.html.HtmlAnchor;
import org.htmlunit.html.HtmlForm;
import org.htmlunit.html.HtmlPage;
import hudson.model.Result;
import hudson.model.Run;
import hudson.model.TaskListener;
import io.jenkins.plugins.oidc_provider.config.BooleanClaimType;
import io.jenkins.plugins.oidc_provider.config.IntegerClaimType;
import io.jenkins.plugins.oidc_provider.config.StringClaimType;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

import java.math.BigInteger;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import jenkins.model.Jenkins;
import static jenkins.test.RunMatchers.logContains;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.hamcrest.MatcherAssert.assertThat;
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;
import org.jenkinsci.plugins.workflow.job.WorkflowRun;
import org.jenkinsci.plugins.workflow.support.actions.EnvironmentAction;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.MockAuthorizationStrategy;
import org.jvnet.hudson.test.TestExtension;
import org.jvnet.hudson.test.junit.jupiter.BuildWatcherExtension;
import org.jvnet.hudson.test.junit.jupiter.JenkinsSessionExtension;

class IdTokenCredentialsTest {

    @SuppressWarnings("unused")
    @RegisterExtension
    private static final BuildWatcherExtension BUILD_WATCHER = new BuildWatcherExtension();

    @RegisterExtension
    private final JenkinsSessionExtension rr = new JenkinsSessionExtension();

    @Test
    void persistence() throws Throwable {
        AtomicReference<BigInteger> modulus = new AtomicReference<>();
        rr.then(r -> {
            IdTokenStringCredentials c = new IdTokenStringCredentials(CredentialsScope.GLOBAL, "test", null);
            c.setIssuer("https://issuer");
            c.setAudience("https://audience");
            CredentialsProvider.lookupStores(r.jenkins).iterator().next().addCredentials(Domain.global(), c);
            modulus.set(c.publicKey().getModulus());
        });
        rr.then(r -> {
            List<IdTokenStringCredentials> creds = CredentialsProvider.lookupCredentialsInItemGroup(IdTokenStringCredentials.class, r.jenkins, null, Collections.emptyList());
            assertThat(creds, hasSize(1));
            assertThat(creds.get(0).getId(), is("test"));
            assertThat(creds.get(0).getIssuer(), is("https://issuer"));
            assertThat(creds.get(0).getAudience(), is("https://audience"));
            assertThat("private key retained by serialization", creds.get(0).publicKey().getModulus(), is(modulus.get()));
            HtmlForm form = r.createWebClient().goTo("credentials/store/system/domain/_/credential/test/update").getFormByName("update");
            form.getInputByName("_.description").setValue("my creds");
            r.submit(form);
            creds = CredentialsProvider.lookupCredentialsInItemGroup(IdTokenStringCredentials.class, r.jenkins, null, Collections.emptyList());
            assertThat(creds, hasSize(1));
            assertThat(creds.get(0).getDescription(), is("my creds"));
            assertThat("private key rotated by resaving", creds.get(0).publicKey().getModulus(), is(not(modulus.get())));
            creds.get(0).setIssuer(null);
            creds.get(0).setAudience(null);
            r.submit(r.createWebClient().goTo("credentials/store/system/domain/_/credential/test/update").getFormByName("update"));
            creds = CredentialsProvider.lookupCredentialsInItemGroup(IdTokenStringCredentials.class, r.jenkins, null, Collections.emptyList());
            assertThat(creds, hasSize(1));
            assertThat(creds.get(0).getIssuer(), is(nullValue()));
            assertThat(creds.get(0).getAudience(), is(nullValue()));
        });
    }

    @Test
    void checkIssuer() throws Throwable {
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

    @Test
    void tokenLifetime() throws Throwable {
        rr.then(r -> {
            IdTokenStringCredentials c = new IdTokenStringCredentials(CredentialsScope.GLOBAL, "test", null);
            CredentialsProvider.lookupStores(r.jenkins).iterator().next().addCredentials(Domain.global(), c);
            IdTokenConfiguration cfg = IdTokenConfiguration.get();
            cfg.setTokenLifetime(60);
            String idToken = c.getSecret().getPlainText();
            System.out.println(idToken);
            Claims claims = Jwts.parserBuilder().
                setSigningKey(c.publicKey()).
                build().
                parseClaimsJws(idToken).
                getBody();

            assertTrue(Instant.now().plus(61, ChronoUnit.SECONDS).isAfter(claims.getExpiration().toInstant()));
        });
    }

    @Test
    void customClaims() throws Throwable {
        rr.then(r -> {
            IdTokenStringCredentials c = new IdTokenStringCredentials(CredentialsScope.GLOBAL, "test", null);
            CredentialsProvider.lookupStores(r.jenkins).iterator().next().addCredentials(Domain.global(), c);
            IdTokenConfiguration cfg = IdTokenConfiguration.get();
            cfg.setClaimTemplates(Collections.singletonList(new ClaimTemplate("ok", "true", new BooleanClaimType())));
            cfg.setGlobalClaimTemplates(Collections.singletonList(new ClaimTemplate("sub", "jenkins", new StringClaimType())));
            cfg.setBuildClaimTemplates(Arrays.asList(new ClaimTemplate("sub", "${JOB_NAME}", new StringClaimType()), new ClaimTemplate("num", "${BUILD_NUMBER}", new IntegerClaimType())));
            String idToken = c.getSecret().getPlainText();
            System.out.println(idToken);
            Claims claims = Jwts.parserBuilder().
                setSigningKey(c.publicKey()).
                build().
                parseClaimsJws(idToken).
                getBody();
            System.out.println(claims);
            assertEquals(r.jenkins.getRootUrl() + "oidc", claims.getIssuer());
            assertEquals("jenkins", claims.getSubject());
            assertTrue(claims.get("ok", Boolean.class));
            WorkflowJob p = r.createProject(Folder.class, "dir").createProject(WorkflowJob.class, "p");
            p.setDefinition(new CpsFlowDefinition("withCredentials([string(variable: 'TOK', credentialsId: 'test')]) {env.TOK = TOK}", true));
            WorkflowRun b = r.buildAndAssertSuccess(p);
            EnvironmentAction env = b.getAction(EnvironmentAction.class);
            idToken = env.getEnvironment().get("TOK");
            System.out.println(idToken);
            claims = Jwts.parserBuilder().
                setSigningKey(c.publicKey()).
                build().
                parseClaimsJws(idToken).
                getBody();
            System.out.println(claims);
            assertEquals(r.jenkins.getRootUrl() + "oidc", claims.getIssuer());
            assertEquals("dir/p", claims.getSubject());
            assertEquals(1, claims.get("num", Integer.class).intValue());
            assertTrue(claims.get("ok", Boolean.class));
        });
    }

    @Test
    void invalidCustomClaims() throws Throwable {
        rr.then(r -> {
            CredentialsProvider.lookupStores(r.jenkins).iterator().next().addCredentials(Domain.global(), new IdTokenStringCredentials(CredentialsScope.GLOBAL, "test", null));
            WorkflowJob p = r.createProject(WorkflowJob.class, "p");
            p.setDefinition(new CpsFlowDefinition("withCredentials([string(variable: 'TOK', credentialsId: 'test')]) {echo(/should not get $TOK/)}", true));
            IdTokenConfiguration cfg = IdTokenConfiguration.get();
            cfg.setClaimTemplates(Collections.singletonList(new ClaimTemplate("iss", "oops must not be overridden", new StringClaimType())));
            r.assertLogContains("must not specify iss", r.buildAndAssertStatus(Result.FAILURE, p));
            cfg.setClaimTemplates(Collections.emptyList());
            cfg.setBuildClaimTemplates(Collections.singletonList(new ClaimTemplate("stuff", "fine but where is sub?", new StringClaimType())));
            r.assertLogContains("must specify sub", r.buildAndAssertStatus(Result.FAILURE, p));
        });
    }

    @Issue("SECURITY-3574")
    @Test
    void spoofedClaimsRunLevel() throws Throwable {
        rr.then(r -> {
            var c = new IdTokenStringCredentials(CredentialsScope.GLOBAL, "test", null);
            CredentialsProvider.lookupStores(r.jenkins).iterator().next().addCredentials(Domain.global(), c);
            var p = r.createProject(Folder.class, "dir").createProject(WorkflowJob.class, "p");
            p.setDefinition(new CpsFlowDefinition("withCredentials([string(variable: 'TOK', credentialsId: 'test')]) {env.TOK = TOK}", true));
            var b = r.buildAndAssertSuccess(p);
            var idToken = b.getAction(EnvironmentAction.class).getEnvironment().get("TOK");
            System.out.println(idToken);
            var claims = Jwts.parserBuilder().
                setSigningKey(c.publicKey()).
                build().
                parseClaimsJws(idToken).
                getBody();
            System.out.println(claims);
            assertEquals(/* p.getAbsoluteUrl() */ "${JOB_URL}", claims.getSubject());
            assertThat(b, logContains("Refusing to consider conflicting values"));
        });
    }

    @SuppressWarnings("unused")
    @TestExtension("spoofedClaimsRunLevel")
    public static final class RunSpoofer extends EnvironmentContributor {

        @Override
        public void buildEnvironmentFor(@NonNull Run r, @NonNull EnvVars envs, @NonNull TaskListener listener) {
            envs.put("JOB_URL", "https://bogus.com/");
        }
    }

    @Issue("SECURITY-3574")
    @Test
    void spoofedClaimsJobLevel() throws Throwable {
        rr.then(r -> {
            var c = new IdTokenStringCredentials(CredentialsScope.GLOBAL, "test", null);
            CredentialsProvider.lookupStores(r.jenkins).iterator().next().addCredentials(Domain.global(), c);
            var p = r.createProject(Folder.class, "dir").createProject(WorkflowJob.class, "p");
            p.setDefinition(new CpsFlowDefinition("withCredentials([string(variable: 'TOK', credentialsId: 'test')]) {env.TOK = TOK}", true));
            var b = r.buildAndAssertSuccess(p);
            var idToken = b.getAction(EnvironmentAction.class).getEnvironment().get("TOK");
            System.out.println(idToken);
            var claims = Jwts.parserBuilder().
                setSigningKey(c.publicKey()).
                build().
                parseClaimsJws(idToken).
                getBody();
            System.out.println(claims);
            assertEquals(/* p.getAbsoluteUrl() */ "${JOB_URL}", claims.getSubject());
            assertThat(b, logContains("Refusing to consider conflicting values"));
        });
    }

    @SuppressWarnings("unused")
    @TestExtension("spoofedClaimsJobLevel")
    public static final class JobSpoofer extends EnvironmentContributor {

        @Override
        public void buildEnvironmentFor(@NonNull Job j, @NonNull EnvVars envs, @NonNull TaskListener listener) {
            envs.put("JOB_URL", "https://bogus.com/");
        }
    }

    @Test
    void scmClaims() throws Throwable {
        rr.then(r -> {
            var c = new IdTokenStringCredentials(CredentialsScope.GLOBAL, "test", null);
            CredentialsProvider.lookupStores(r.jenkins).iterator().next().addCredentials(Domain.global(), c);
            var cfg = IdTokenConfiguration.get();
            cfg.setBuildClaimTemplates(Arrays.asList(
                new ClaimTemplate("sub", "${JOB_NAME}", new StringClaimType()),
                new ClaimTemplate("git_url", "${GIT_URL}", new StringClaimType()),
                new ClaimTemplate("git_branch", "${GIT_BRANCH}", new StringClaimType()),
                new ClaimTemplate("git_commit", "${GIT_COMMIT}", new StringClaimType())
            ));
            
            var p = r.createProject(WorkflowJob.class, "p");
            p.setDefinition(new CpsFlowDefinition(
                "withCredentials([string(variable: 'TOK', credentialsId: 'test')]) {env.TOK = TOK}", 
                true));
            var b = r.buildAndAssertSuccess(p);
            var idToken = b.getAction(EnvironmentAction.class).getEnvironment().get("TOK");
            System.out.println(idToken);
            var claims = Jwts.parserBuilder().
                setSigningKey(c.publicKey()).
                build().
                parseClaimsJws(idToken).
                getBody();
            System.out.println(claims);
            
            assertEquals("https://github.com/example/repo.git", claims.get("git_url", String.class));
            assertEquals("origin/main", claims.get("git_branch", String.class));
            assertEquals("abc123def456", claims.get("git_commit", String.class));
        });
    }

    @SuppressWarnings("unused")
    @TestExtension("scmClaims")
    public static final class GitScmContributor extends EnvironmentContributor {

        @Override
        public void buildEnvironmentFor(@NonNull Run r, @NonNull EnvVars envs, @NonNull TaskListener listener) {
            envs.put("GIT_URL", "https://github.com/example/repo.git");
            envs.put("GIT_BRANCH", "origin/main");
            envs.put("GIT_COMMIT", "abc123def456");
        }
    }

    @Issue("SECURITY-3574")
    @Test
    void spoofedClaimsScmLevel() throws Throwable {
        rr.then(r -> {
            var c = new IdTokenStringCredentials(CredentialsScope.GLOBAL, "test", null);
            CredentialsProvider.lookupStores(r.jenkins).iterator().next().addCredentials(Domain.global(), c);
            var cfg = IdTokenConfiguration.get();
            cfg.setBuildClaimTemplates(Arrays.asList(
                new ClaimTemplate("sub", "${JOB_NAME}", new StringClaimType()),
                new ClaimTemplate("git_url", "${GIT_URL}", new StringClaimType())
            ));
            
            var p = r.createProject(WorkflowJob.class, "p");
            p.setDefinition(new CpsFlowDefinition(
                "withCredentials([string(variable: 'TOK', credentialsId: 'test')]) {env.TOK = TOK}",
                true));
            var b = r.buildAndAssertSuccess(p);
            
            assertThat(b, logContains("Refusing to consider conflicting values"));
            
            var idToken = b.getAction(EnvironmentAction.class).getEnvironment().get("TOK");
            System.out.println(idToken);
            var claims = Jwts.parserBuilder().
                setSigningKey(c.publicKey()).
                build().
                parseClaimsJws(idToken).
                getBody();
            System.out.println(claims);
            
            assertEquals("${GIT_URL}", claims.get("git_url", String.class));
        });
    }

    @SuppressWarnings("unused")
    @TestExtension("spoofedClaimsScmLevel")
    public static final class ScmSpooferRun extends EnvironmentContributor {

        @Override
        public void buildEnvironmentFor(@NonNull Run r, @NonNull EnvVars envs, @NonNull TaskListener listener) {
            envs.put("GIT_URL", "https://github.com/run-level/repo.git");
        }
    }

    @SuppressWarnings("unused")
    @TestExtension("spoofedClaimsScmLevel")
    public static final class ScmSpooferJob extends EnvironmentContributor {

        @Override
        public void buildEnvironmentFor(@NonNull Job j, @NonNull EnvVars envs, @NonNull TaskListener listener) {
            envs.put("GIT_URL", "https://github.com/job-level/repo.git");
        }
    }
}
