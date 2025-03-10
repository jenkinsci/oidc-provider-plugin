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
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;
import org.jenkinsci.plugins.workflow.job.WorkflowRun;
import org.jenkinsci.plugins.workflow.support.actions.EnvironmentAction;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@WithJenkins
class IdTokenStringCredentialsTest {

    @Test
    void smokes(JenkinsRule r) throws Exception {
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
    }

    @Test
    void declarative(JenkinsRule r) throws Exception {
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

    @Test
    void alternateIssuer(JenkinsRule r) throws Exception {
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
    }

}
