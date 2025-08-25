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
import hudson.slaves.DumbSlave;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;
import org.jenkinsci.plugins.workflow.job.WorkflowRun;
import org.jenkinsci.plugins.workflow.support.actions.EnvironmentAction;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.BuildWatcherExtension;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

@WithJenkins
class IdTokenFileCredentialsTest {

    @SuppressWarnings("unused")
    @RegisterExtension
    private static final BuildWatcherExtension BUILD_WATCHER = new BuildWatcherExtension();

    private JenkinsRule r;

    @BeforeEach
    void beforeEach(JenkinsRule rule) {
        r = rule;
    }

    @Test
    void smokes() throws Exception {
        IdTokenFileCredentials c = new IdTokenFileCredentials(CredentialsScope.GLOBAL, "test", null);
        c.setAudience("https://service/");
        CredentialsProvider.lookupStores(r.jenkins).iterator().next().addCredentials(Domain.global(), c);
        r.createSlave("remote", null, null);
        WorkflowJob p = r.createProject(WorkflowJob.class, "p");
        p.setDefinition(new CpsFlowDefinition(
                """
                        node('remote') {
                          withCredentials([file(variable: 'ID_TOKEN_FILE', credentialsId: 'test')]) {
                            echo(/binding id token file $ID_TOKEN_FILE/)
                            env.RESULT = readFile ID_TOKEN_FILE
                          }
                        }""", true));
        WorkflowRun b = r.buildAndAssertSuccess(p);
        r.assertLogContains("binding id token file ****", b);
        EnvironmentAction env = b.getAction(EnvironmentAction.class);
        assertNotNull(env);
        String idToken = env.getEnvironment().get("RESULT");
        assertNotNull(idToken);
        Claims claims = Jwts.parserBuilder().
            setSigningKey(c.publicKey()).
            build().
            parseClaimsJws(idToken).
            getBody();
        assertEquals(r.jenkins.getRootUrl() + "oidc", claims.getIssuer());
    }

    @Test
    void declarative() throws Exception {
        IdTokenFileCredentials c = new IdTokenFileCredentials(CredentialsScope.GLOBAL, "test", null);
        c.setAudience("https://service/");
        CredentialsProvider.lookupStores(r.jenkins).iterator().next().addCredentials(Domain.global(), c);
        DumbSlave s = r.createSlave("remote", null, null);
        WorkflowJob p = r.createProject(WorkflowJob.class, "p");
        p.setDefinition(new CpsFlowDefinition("pipeline {\n" +
            "  agent {\n" +
            "    label 'remote'\n" +
            "  }\n" +
            "  environment {\n" +
            "    ID_TOKEN_FILE=credentials('test')\n" +
            "  }\n" +
            "  stages {\n" +
            "    stage('all') {\n" +
            "      steps {\n" +
            "        writeFile(file: 'tok', text: readFile(ID_TOKEN_FILE))\n" + // or Linux: sh 'cp $ID_TOKEN_FILE tok'
            "      }\n" +
            "    }\n" +
            "  }\n" +
            "}", true));
        WorkflowRun b = r.buildAndAssertSuccess(p);
        String idToken = s.getWorkspaceFor(p).child("tok").readToString();
        Claims claims = Jwts.parserBuilder().
            setSigningKey(c.publicKey()).
            build().
            parseClaimsJws(idToken).
            getBody();
        System.out.println(claims);
    }
}
