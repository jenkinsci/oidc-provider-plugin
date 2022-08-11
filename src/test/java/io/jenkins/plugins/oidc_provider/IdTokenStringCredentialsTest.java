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
import com.cloudbees.plugins.credentials.domains.Domain;
import com.google.common.collect.ListMultimap;

import hudson.Extension;
import hudson.FilePath;
import hudson.model.AbstractBuild;
import hudson.model.Run;
import hudson.model.TaskListener;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.junit.ClassRule;
import org.junit.Test;
import org.jenkinsci.plugins.tokenmacro.MacroEvaluationException;
import org.jenkinsci.plugins.tokenmacro.TokenMacro;
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;
import org.jenkinsci.plugins.workflow.job.WorkflowRun;
import org.jenkinsci.plugins.workflow.support.actions.EnvironmentAction;
import static org.junit.Assert.*;

import java.io.IOException;
import java.util.Map;

import org.junit.Rule;
import org.jvnet.hudson.test.BuildWatcher;
import org.jvnet.hudson.test.JenkinsRule;

public class IdTokenStringCredentialsTest {

    @ClassRule public static BuildWatcher buildWatcher = new BuildWatcher();

    @Rule public JenkinsRule r = new JenkinsRule();

    @Test public void smokes() throws Exception {
        IdTokenStringCredentials c = new IdTokenStringCredentials(CredentialsScope.GLOBAL, "test", null);
        c.setAudience("https://service/");
        CredentialsProvider.lookupStores(r.jenkins).iterator().next().addCredentials(Domain.global(), c);
        WorkflowJob p = r.createProject(WorkflowJob.class, "p");
        p.setDefinition(new CpsFlowDefinition("withCredentials([string(variable: 'ID_TOKEN', credentialsId: 'test')]) {echo(/binding id token $ID_TOKEN/); env.RESULT = ID_TOKEN}", true));
        WorkflowRun b = r.buildAndAssertSuccess(p);
        r.assertLogContains("binding id token ****", b);
        EnvironmentAction env = b.getAction(EnvironmentAction.class);
        assertNotNull(env);
        String idToken = env.getEnvironment().get("RESULT");
        assertNotNull(idToken);
        System.out.println(idToken);
        Claims claims = Jwts.parserBuilder().
            setSigningKey(c.publicKey()).
            build().
            parseClaimsJws(idToken).
            getBody();
        System.out.println(claims);
        assertEquals(r.jenkins.getRootUrl() + "oidc", claims.getIssuer());
        assertEquals(p.getAbsoluteUrl(), claims.getSubject());
        assertEquals("https://service/", claims.getAudience());
        assertEquals(1, claims.get("build_number", Integer.class).intValue());
        assertEquals("my_git_revision", claims.get("git_revision", String.class));
        assertEquals("my_git_branch", claims.get("git_branch", String.class));
    }

    @Test public void declarative() throws Exception {
        IdTokenStringCredentials c = new IdTokenStringCredentials(CredentialsScope.GLOBAL, "test", null);
        c.setAudience("https://service/");
        CredentialsProvider.lookupStores(r.jenkins).iterator().next().addCredentials(Domain.global(), c);
        WorkflowJob p = r.createProject(WorkflowJob.class, "p");
        p.setDefinition(new CpsFlowDefinition("pipeline {\n" +
            "  agent any\n" +
            "  environment {\n" +
            "    ID_TOKEN=credentials('test')\n" +
            "  }\n" +
            "  stages {\n" +
            "    stage('all') {\n" +
            "      steps {\n" +
            "        writeFile file: 'tok', text: ID_TOKEN\n" + // or Linux: sh 'echo -n $ID_TOKEN > tok'
            "      }\n" +
            "    }\n" +
            "  }\n" +
            "}", true));
        WorkflowRun b = r.buildAndAssertSuccess(p);
        String idToken = r.jenkins.getWorkspaceFor(p).child("tok").readToString();
        Claims claims = Jwts.parserBuilder().
            setSigningKey(c.publicKey()).
            build().
            parseClaimsJws(idToken).
            getBody();
        System.out.println(claims);
        assertEquals(1, claims.get("build_number", Integer.class).intValue());
    }

    @Test public void alternateIssuer() throws Exception {
        IdTokenStringCredentials c = new IdTokenStringCredentials(CredentialsScope.GLOBAL, "test", null);
        c.setIssuer("https://some.issuer");
        CredentialsProvider.lookupStores(r.jenkins).iterator().next().addCredentials(Domain.global(), c);
        WorkflowJob p = r.createProject(WorkflowJob.class, "p");
        p.setDefinition(new CpsFlowDefinition("withCredentials([string(variable: 'ID_TOKEN', credentialsId: 'test')]) {env.RESULT = ID_TOKEN}", true));
        WorkflowRun b = r.buildAndAssertSuccess(p);
        EnvironmentAction env = b.getAction(EnvironmentAction.class);
        assertNotNull(env);
        String idToken = env.getEnvironment().get("RESULT");
        assertNotNull(idToken);
        Claims claims = Jwts.parserBuilder().
            setSigningKey(c.publicKey()).
            build().
            parseClaimsJws(idToken).
            getBody();
        System.out.println(claims);
        assertEquals("https://some.issuer", claims.getIssuer());
        assertEquals(p.getAbsoluteUrl(), claims.getSubject());
        assertEquals("my_git_revision", claims.get("git_revision", String.class));
        assertEquals("my_git_branch", claims.get("git_branch", String.class));
    }

    @Extension
    public static class GitTokenMacro extends TokenMacro {

        @Override
        public boolean acceptsMacroName(String macroName) {
            return true;
        }

        @Override
        public String evaluate(Run<?, ?> run, FilePath workspace, TaskListener listener, String macroName,
                Map<String, String> arguments, ListMultimap<String, String> argumentMultimap)
                throws MacroEvaluationException, IOException, InterruptedException {
            return String.format("my_%s", macroName.toLowerCase());
        }

        @Override
        public String evaluate(AbstractBuild<?, ?> context, TaskListener listener, String macroName,
                Map<String, String> arguments, ListMultimap<String, String> argumentMultimap)
                throws MacroEvaluationException, IOException, InterruptedException {
            return String.format("my_%s", macroName.toLowerCase());
        }

    }

}
