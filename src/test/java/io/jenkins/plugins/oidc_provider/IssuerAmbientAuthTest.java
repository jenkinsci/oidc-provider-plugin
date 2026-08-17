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
import edu.umd.cs.findbugs.annotations.CheckForNull;
import hudson.ExtensionList;
import hudson.model.Cause;
import hudson.model.CauseAction;
import hudson.model.FreeStyleBuild;
import hudson.model.FreeStyleProject;
import hudson.model.Item;
import hudson.model.Queue;
import hudson.model.User;
import hudson.security.ACL;
import hudson.security.ACLContext;
import io.jsonwebtoken.Jwts;
import java.util.List;
import java.util.logging.Level;
import jenkins.model.Jenkins;
import jenkins.security.QueueItemAuthenticator;
import jenkins.security.QueueItemAuthenticatorConfiguration;
import jenkins.security.QueueItemAuthenticatorDescriptor;
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition;
import org.jenkinsci.plugins.workflow.flow.FlowExecution;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;
import org.jenkinsci.plugins.workflow.job.WorkflowRun;
import org.jenkinsci.plugins.workflow.support.actions.EnvironmentAction;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.LogRecorder;
import org.jvnet.hudson.test.MockAuthorizationStrategy;
import org.jvnet.hudson.test.TestExtension;
import org.jvnet.hudson.test.junit.jupiter.BuildWatcherExtension;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.springframework.security.core.Authentication;

/**
 * Verifies that minting an ID token does not depend on the <em>ambient</em> {@link Authentication}
 * of the thread that happens to be running the build.
 *
 * <p>{@link Issuer#credentials} enumerates a {@link com.cloudbees.plugins.credentials.CredentialsStore}
 * via {@code store.getCredentials(Domain.global())}, an API which takes no {@link Authentication}
 * argument and therefore resolves against whatever identity is current on the calling thread.
 * {@code SystemCredentialsProvider.getCredentials(Domain)} is guarded by
 * {@code if (Jenkins.get().hasPermission(CredentialsProvider.VIEW))} and otherwise returns
 * {@link java.util.Collections#emptyList} <em>silently</em>. When a build runs as a user who lacks
 * {@link CredentialsProvider#VIEW} at the root, {@link IdTokenCredentials#findIssuer} therefore finds
 * no issuer whose {@code credentials()} contains the credential and throws the badly misleading
 * {@code IllegalStateException: Could not find issuer corresponding to <id> for <job>#<n>} —
 * even though credentials-binding already resolved that very credential by ID as {@link ACL#SYSTEM2}.
 *
 * <p>Note that {@link CredentialsProvider#VIEW} is {@code impliedBy} {@link hudson.security.Permission#READ},
 * which is {@code impliedBy} {@link Jenkins#ADMINISTER}. <strong>Every</strong> other authorization-aware
 * test in this plugin grants {@code Jenkins.ADMINISTER} everywhere, which is precisely why this branch
 * has never been exercised. The tests below deliberately grant neither {@code Jenkins.ADMINISTER}
 * nor {@code CredentialsProvider.VIEW}.
 */
@WithJenkins
class IssuerAmbientAuthTest {

    private static final String NON_ADMIN = "dev";

    @SuppressWarnings("unused")
    @RegisterExtension
    private static final BuildWatcherExtension BUILD_WATCHER = new BuildWatcherExtension();

    private final LogRecorder logging = new LogRecorder().recordPackage(Issuer.class, Level.FINE).capture(100);

    private JenkinsRule r;

    @BeforeEach
    void beforeEach(JenkinsRule rule) {
        r = rule;
    }

    /**
     * Locks down the security setup itself, so that a future edit which quietly widens the grant
     * (and thus stops reproducing the defect) fails loudly instead of passing vacuously.
     */
    private Authentication nonAdmin() {
        r.jenkins.setSecurityRealm(r.createDummySecurityRealm());
        r.jenkins.setAuthorizationStrategy(new MockAuthorizationStrategy()
            // Deliberately NOT Jenkins.ADMINISTER and NOT CredentialsProvider.VIEW.
            .grant(Jenkins.READ, Item.READ, Item.BUILD).everywhere().to(NON_ADMIN));
        User u = User.getById(NON_ADMIN, true);
        assertNotNull(u);
        Authentication auth = u.impersonate2();
        assertFalse(r.jenkins.getACL().hasPermission2(auth, Jenkins.ADMINISTER),
            "test is only meaningful if " + NON_ADMIN + " is not an administrator");
        assertFalse(r.jenkins.getACL().hasPermission2(auth, CredentialsProvider.VIEW),
            "test is only meaningful if " + NON_ADMIN + " lacks CredentialsProvider.VIEW at the root");
        return auth;
    }

    private IdTokenStringCredentials globalCredentials() throws Exception {
        IdTokenStringCredentials c = new IdTokenStringCredentials(CredentialsScope.GLOBAL, "test", null);
        c.setAudience("https://service/");
        CredentialsProvider.lookupStores(r.jenkins).iterator().next().addCredentials(Domain.global(), c);
        return c;
    }

    /**
     * Unit-level probe of {@link IdTokenCredentials#findIssuer}: resolving the issuer of an
     * already-bound credential must not depend on the ambient authentication of the calling thread.
     * Before the fix this throws {@code IllegalStateException: Could not find issuer corresponding to
     * test for p#1}.
     *
     * <p>Deliberately asserts on {@code findIssuer()} rather than on {@link Issuer#credentials} so that
     * it holds for either shape of the fix (escalating inside {@code findIssuer}, or escalating inside
     * {@code Issuer.credentials}).
     */
    @Test
    void issuerLookupIgnoresAmbientAuthentication() throws Exception {
        IdTokenStringCredentials c = globalCredentials();
        FreeStyleProject p = r.createFreeStyleProject("p");
        FreeStyleBuild b = r.buildAndAssertSuccess(p);
        // Sanity: the credential really is in the global store. Impersonate explicitly, because
        // JenkinsExtension (the @WithJenkins path) does not impersonate ACL.SYSTEM2 on the test thread
        // the way JenkinsRule.apply() does for JUnit 4; the ambient identity would be ANONYMOUS2.
        try (ACLContext ignored = ACL.as2(ACL.SYSTEM2)) {
            assertThat("sanity: the credential is in the global store",
                ids(ExtensionList.lookupSingleton(RootIssuer.class)), contains("test"));
        }
        Authentication auth = nonAdmin();
        // forRun() is what CredentialsProvider.contextualize does, i.e. only ever *after* the by-ID
        // lookup in findCredentialById has already authorized the credential as ACL.SYSTEM2.
        IdTokenCredentials bound = (IdTokenCredentials) c.forRun(b);
        try (ACLContext ignored = ACL.as2(auth)) {
            assertEquals(r.jenkins.getRootUrl() + "oidc", bound.findIssuer().url(),
                "findIssuer() must not depend on the ambient authentication holding CredentialsProvider.VIEW");
        }
    }

    private static List<String> ids(Issuer issuer) {
        return issuer.credentials().stream().map(IdTokenCredentials::getId).toList();
    }

    /**
     * End-to-end reproduction: a Pipeline build authenticated as a non-administrator binds a global
     * ID token credential. Before the fix this fails with
     * {@code IllegalStateException: Could not find issuer corresponding to test for p#1}.
     */
    @Test
    void tokenMintedForBuildRunningAsNonAdministrator() throws Exception {
        IdTokenStringCredentials c = globalCredentials();
        WorkflowJob p = r.createProject(WorkflowJob.class, "p");
        p.setDefinition(new CpsFlowDefinition(
            "withCredentials([string(variable: 'ID_TOKEN', credentialsId: 'test')]) {env.RESULT = ID_TOKEN}", true));
        nonAdmin();
        QueueItemAuthenticatorConfiguration.get().getAuthenticators().add(new TriggeringUserAuthenticator());

        WorkflowRun b = r.assertBuildStatusSuccess(
            p.scheduleBuild2(0, new CauseAction(new Cause.UserIdCause(NON_ADMIN))));

        // Guard: the whole point is that the build really did run as the non-administrator.
        FlowExecution exec = b.getExecution();
        assertNotNull(exec);
        assertEquals(NON_ADMIN, exec.getAuthentication2().getName(),
            "build must run as the non-administrator, otherwise this test proves nothing");

        EnvironmentAction env = b.getAction(EnvironmentAction.class);
        assertNotNull(env);
        String idToken = env.getEnvironment().get("RESULT");
        assertNotNull(idToken, "an ID token should have been minted and bound");
        assertFalse(idToken.isEmpty());
        var claims = Jwts.parser().verifyWith(c.publicKey()).build().parseSignedClaims(idToken).getPayload();
        assertEquals(r.jenkins.getRootUrl() + "oidc", claims.getIssuer());
        assertEquals(p.getAbsoluteUrl(), claims.getSubject());
        assertThat(claims.getAudience(), contains("https://service/"));

        // The plugin's own FINE logging is the direct witness of the mechanism: before the fix this
        // reads "found []" for the same store instance that reports "found [test]" for an administrator.
        assertThat(logging, LogRecorder.recorded(containsString("found [test]")));
    }

    /**
     * Stands in for {@code authorize-project}'s {@code ProjectQueueItemAuthenticator} combined with
     * {@code TriggeringUsersAuthorizationStrategy} ("Run as User who Triggered Build"), and reproduces
     * the asymmetry that the defect depends on:
     * <ul>
     * <li>{@link #authenticate2(Queue.Item)} answers for the <em>real</em> queue item, so
     *     {@code Executor.run()} runs the build — and hence the CPS VM thread — as that user.</li>
     * <li>{@link #authenticate2(Queue.Task)} answers {@code null}, so
     *     {@code CredentialsProvider.getDefaultAuthenticationOf2(Queue.Task)} falls back to
     *     {@link ACL#SYSTEM2} and the by-ID lookup in {@code CredentialsProvider.findCredentialById}
     *     always succeeds. This mirrors production: core's default {@code authenticate2(Queue.Task)}
     *     synthesises a {@code Queue.WaitingItem} with no actions, so a cause-driven strategy cannot
     *     identify a triggering user and returns {@code null}.</li>
     * </ul>
     * Do <em>not</em> replace this with {@code MockQueueItemAuthenticator}: that one keys off the job
     * name, so it answers identically for the synthetic task item, which makes the by-ID lookup fail
     * first and masks the issuer bug behind a different error.
     */
    public static final class TriggeringUserAuthenticator extends QueueItemAuthenticator {

        @Override
        public @CheckForNull Authentication authenticate2(Queue.Item item) {
            CauseAction ca = item.getAction(CauseAction.class);
            if (ca == null) {
                return null;
            }
            for (Cause cause : ca.getCauses()) {
                if (cause instanceof Cause.UserIdCause uic && uic.getUserId() != null) {
                    User u = User.getById(uic.getUserId(), false);
                    return u != null ? u.impersonate2() : Jenkins.ANONYMOUS2;
                }
            }
            return null;
        }

        @Override
        public @CheckForNull Authentication authenticate2(Queue.Task task) {
            // A bare task carries no build cause, so this strategy cannot name a user. Returning null
            // makes Tasks.getAuthenticationOf2 fall back to Queue.Task.getDefaultAuthentication2(),
            // i.e. ACL.SYSTEM2 — exactly as happens in production.
            return null;
        }

        @TestExtension
        public static final class DescriptorImpl extends QueueItemAuthenticatorDescriptor {}
    }
}
