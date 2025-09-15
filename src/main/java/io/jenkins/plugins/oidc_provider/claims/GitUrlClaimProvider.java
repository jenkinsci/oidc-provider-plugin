package io.jenkins.plugins.oidc_provider.claims;

import hudson.EnvVars;
import hudson.Extension;
import hudson.model.Run;
import hudson.model.TaskListener;

import java.io.IOException;
import java.util.Collections;
import java.util.Map;

public class GitUrlClaimProvider extends ClaimProvider {

    @Override
    public Map<String, Object> getClaims(Run<?, ?> run, TaskListener listener) throws IOException, InterruptedException {
        EnvVars env = run.getEnvironment(listener);
        String gitUrl = env.get("GIT_URL");
        if (gitUrl != null) {
            return Collections.singletonMap("git_url", (Object) gitUrl);
        }
        return Collections.emptyMap();
    }

    @Extension
    public static class DescriptorImpl extends ClaimProviderDescriptor {
        @Override
        public String getDisplayName() {
            return "Git URL Claim Provider";
        }
    }
}