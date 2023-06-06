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
import org.htmlunit.Page;
import hudson.model.ParametersAction;
import hudson.model.ParametersDefinitionProperty;
import hudson.model.StringParameterDefinition;
import hudson.model.StringParameterValue;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import java.net.URL;
import java.util.logging.Level;
import jenkins.model.Jenkins;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.junit.ClassRule;
import org.junit.Test;
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;
import org.jenkinsci.plugins.workflow.job.WorkflowRun;
import org.jenkinsci.plugins.workflow.support.actions.EnvironmentAction;
import static org.junit.Assert.*;
import org.junit.Rule;
import org.jvnet.hudson.test.BuildWatcher;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.LoggerRule;
import org.jvnet.hudson.test.MockAuthorizationStrategy;

public class FolderIssuerTest {

    @ClassRule public static BuildWatcher buildWatcher = new BuildWatcher();
    @Rule public JenkinsRule r = new JenkinsRule();
    @Rule public LoggerRule logging = new LoggerRule().recordPackage(FolderIssuer.class, Level.FINE);

    @Test public void folderEndpoint() throws Exception {
        CredentialsProvider.lookupStores(r.jenkins).iterator().next().addCredentials(Domain.global(), new IdTokenStringCredentials(CredentialsScope.GLOBAL, "global", null));
        Folder middle = r.jenkins.createProject(Folder.class, "top").createProject(Folder.class, "middle");
        CredentialsProvider.lookupStores(middle).iterator().next().addCredentials(Domain.global(), new IdTokenStringCredentials(CredentialsScope.GLOBAL, "team", null));
        middle.createProject(Folder.class, "bottom");
        r.jenkins.setSecurityRealm(r.createDummySecurityRealm());
        r.jenkins.setAuthorizationStrategy(new MockAuthorizationStrategy().grant(Jenkins.ADMINISTER).everywhere().toAuthenticated());
        JSONObject config = r.getJSON("oidc/job/top/job/middle/.well-known/openid-configuration").getJSONObject();
        System.err.println(config.toString(2));
        assertEquals(r.getURL() + "oidc/job/top/job/middle", config.getString("issuer"));
        JenkinsRule.WebClient wc = r.createWebClient();
        Page p = wc.getPage(new URL(config.getString("jwks_uri")));
        assertEquals("application/json", p.getWebResponse().getContentType());
        JSONObject jwks = JSONObject.fromObject(p.getWebResponse().getContentAsString());
        System.err.println(jwks.toString(2));
        JSONArray keys = jwks.getJSONArray("keys");
        assertEquals(1, keys.size());
        JSONObject key = keys.getJSONObject(0);
        assertEquals("team", key.getString("kid"));
        wc.assertFails("oidc/job/top/.well-known/openid-configuration", 404);
        wc.assertFails("oidc/job/top/job/middle/job/bottom/.well-known/openid-configuration", 404);
    }

    @Test public void build() throws Exception {
        IdTokenStringCredentials global = new IdTokenStringCredentials(CredentialsScope.GLOBAL, "global", null);
        global.setAudience("https://global/");
        CredentialsProvider.lookupStores(r.jenkins).iterator().next().addCredentials(Domain.global(), global);
        Folder top = r.jenkins.createProject(Folder.class, "top");
        CredentialsProvider.lookupStores(top).iterator().next().addCredentials(Domain.global(), new IdTokenStringCredentials(CredentialsScope.GLOBAL, "team", null)); // overridden, ignored
        Folder middle = top.createProject(Folder.class, "middle");
        IdTokenStringCredentials team = new IdTokenStringCredentials(CredentialsScope.GLOBAL, "team", null);
        team.setAudience("https://local/");
        CredentialsProvider.lookupStores(middle).iterator().next().addCredentials(Domain.global(), team);
        Folder bottom = middle.createProject(Folder.class, "bottom");
        WorkflowJob p = bottom.createProject(WorkflowJob.class, "p");
        p.addProperty(new ParametersDefinitionProperty(new StringParameterDefinition("CREDS")));
        p.setDefinition(new CpsFlowDefinition("withCredentials([string(variable: 'ID_TOKEN', credentialsId: CREDS)]) {env.RESULT = ID_TOKEN}", true));
        WorkflowRun b = r.assertBuildStatusSuccess(p.scheduleBuild2(0, new ParametersAction(new StringParameterValue("CREDS", "global"))));
        Claims claims = Jwts.parserBuilder().setSigningKey(global.publicKey()).build().parseClaimsJws(b.getAction(EnvironmentAction.class).getEnvironment().get("RESULT")).getBody();
        System.out.println(claims);
        assertEquals(r.getURL() + "oidc", claims.getIssuer());
        assertEquals(r.getURL() + "job/top/job/middle/job/bottom/job/p/", claims.getSubject());
        assertEquals("https://global/", claims.getAudience());
        b = r.assertBuildStatusSuccess(p.scheduleBuild2(0, new ParametersAction(new StringParameterValue("CREDS", "team"))));
        claims = Jwts.parserBuilder().setSigningKey(team.publicKey()).build().parseClaimsJws(b.getAction(EnvironmentAction.class).getEnvironment().get("RESULT")).getBody();
        System.out.println(claims);
        assertEquals(r.getURL() + "oidc/job/top/job/middle", claims.getIssuer());
        assertEquals(p.getAbsoluteUrl(), claims.getSubject());
        assertEquals("https://local/", claims.getAudience());
    }

}
