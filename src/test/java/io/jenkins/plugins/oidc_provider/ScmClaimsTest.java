/*
 * The MIT License
 *
 * Copyright 2026 CloudBees, Inc.
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
import com.cloudbees.plugins.credentials.domains.Domain;
import hudson.model.ParametersAction;
import hudson.model.ParametersDefinitionProperty;
import hudson.model.StringParameterDefinition;
import hudson.model.StringParameterValue;
import io.jenkins.plugins.oidc_provider.config.ClaimTemplate;
import io.jenkins.plugins.oidc_provider.config.IdTokenConfiguration;
import io.jenkins.plugins.oidc_provider.config.StringClaimType;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import java.util.List;
import jenkins.branch.BranchSource;
import jenkins.plugins.git.GitSCMSource;
import jenkins.plugins.git.GitSampleRepoRule;
import jenkins.plugins.git.junit.jupiter.WithGitSampleRepo;
import jenkins.plugins.git.traits.BranchDiscoveryTrait;
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;
import org.jenkinsci.plugins.workflow.support.actions.EnvironmentAction;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.BuildWatcherExtension;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject;

@WithJenkins
@WithGitSampleRepo
final class ScmClaimsTest {

    @RegisterExtension
    private static final BuildWatcherExtension BUILD_WATCHER = new BuildWatcherExtension();

    @Test void bound(JenkinsRule j, GitSampleRepoRule repo) throws Exception {
        repo.init();
        repo.write("f", "content");
        repo.git("add", "f");
        repo.git("commit", "--message=stuff");
        var commit = repo.head();
        IdTokenConfiguration.get().setBuildClaimTemplates(List.of(new ClaimTemplate(Claims.SUBJECT, "${JOB_URL}", new StringClaimType()), new ClaimTemplate("commit_hash", "${GIT_COMMIT}", new StringClaimType())));
        var c = new IdTokenStringCredentials(CredentialsScope.GLOBAL, "test", null);
        CredentialsProvider.lookupStores(j.jenkins).iterator().next().addCredentials(Domain.global(), c);
        var p = j.createProject(WorkflowJob.class, "p");
        p.setDefinition(new CpsFlowDefinition("""
            node {
              git REPO
              withCredentials([string(variable: 'TOK', credentialsId: 'test')]) {
                env.TOK = TOK
              }
            }
            """, true));
        p.addProperty(new ParametersDefinitionProperty(new StringParameterDefinition("REPO")));
        var b = p.scheduleBuild2(0, new ParametersAction(new StringParameterValue("REPO", repo.toString()))).get();
        j.assertBuildStatusSuccess(b);
        var idToken = b.getAction(EnvironmentAction.class).getEnvironment().get("TOK");
        System.out.println(idToken);
        var claims = Jwts.parser().
                verifyWith(c.publicKey()).
                build().
                parseSignedClaims(idToken).
                getPayload();
        System.out.println(claims);
        assertThat(claims.get("commit_hash", String.class), is(commit));
    }

    @Test void multibranch(JenkinsRule j, GitSampleRepoRule repo) throws Exception {
        repo.init();
        repo.write("Jenkinsfile", """
            withCredentials([string(variable: 'TOK', credentialsId: 'test')]) {
              env.TOK = TOK
            }
            """);
        repo.git("add", "Jenkinsfile");
        repo.git("commit", "--message=stuff");
        var commit = repo.head();
        IdTokenConfiguration.get().setBuildClaimTemplates(List.of(
            new ClaimTemplate(Claims.SUBJECT, "${JOB_URL}", new StringClaimType()),
            new ClaimTemplate("commit", "${SCM_REVISION}", new StringClaimType()),
            new ClaimTemplate("branch", "${BRANCH_NAME}", new StringClaimType())));
        var c = new IdTokenStringCredentials(CredentialsScope.GLOBAL, "test", null);
        CredentialsProvider.lookupStores(j.jenkins).iterator().next().addCredentials(Domain.global(), c);
        var mp = j.createProject(WorkflowMultiBranchProject.class, "p");
        var source = new GitSCMSource(repo.toString());
        source.getTraits().add(new BranchDiscoveryTrait());
        mp.getSourcesList().add(new BranchSource(source));
        j.jenkins.setQuietPeriod(0);
        mp.scheduleBuild2(0).getFuture().get();
        var indexing = mp.getIndexing();
        System.out.println("---%<--- " + indexing.getUrl());
        indexing.writeWholeLogTo(System.out);
        System.out.println("---%<--- ");
        var p = mp.getItem("master");
        j.waitUntilNoActivity();
        var b = p.getLastBuild();
        j.assertBuildStatusSuccess(b);
        var idToken = b.getAction(EnvironmentAction.class).getEnvironment().get("TOK");
        System.out.println(idToken);
        var claims = Jwts.parser().
                verifyWith(c.publicKey()).
                build().
                parseSignedClaims(idToken).
                getPayload();
        System.out.println(claims);
        assertThat(claims.get("commit", String.class), is(commit));
        assertThat(claims.get("branch", String.class), is("master"));
    }

}
