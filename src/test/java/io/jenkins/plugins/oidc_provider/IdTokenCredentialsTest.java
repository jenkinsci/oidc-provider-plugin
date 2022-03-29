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
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import java.math.BigInteger;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.Test;
import static org.hamcrest.Matchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import org.junit.Rule;
import org.jvnet.hudson.test.JenkinsSessionRule;

public class IdTokenCredentialsTest {

    @Rule public JenkinsSessionRule rr = new JenkinsSessionRule();

    @Test public void persistence() throws Throwable {
        AtomicReference<BigInteger> modulus = new AtomicReference<>();
        rr.then(r -> {
            IdTokenStringCredentials c = new IdTokenStringCredentials(CredentialsScope.GLOBAL, "test", null);
            c.setAudience("https://service/");
            CredentialsProvider.lookupStores(r.jenkins).iterator().next().addCredentials(Domain.global(), c);
            modulus.set(c.publicKey().getModulus());
        });
        rr.then(r -> {
            List<IdTokenStringCredentials> creds = CredentialsProvider.lookupCredentials(IdTokenStringCredentials.class, r.jenkins, null, Collections.emptyList());
            assertThat(creds, hasSize(1));
            assertThat(creds.get(0).getId(), is("test"));
            assertThat("private key retained by serialization", creds.get(0).publicKey().getModulus(), is(modulus.get()));
            HtmlForm form = r.createWebClient().goTo("credentials/store/system/domain/_/credential/test/update").getFormByName("update");
            form.getInputByName("_.description").setValueAttribute("my creds");
            r.submit(form);
            creds = CredentialsProvider.lookupCredentials(IdTokenStringCredentials.class, r.jenkins, null, Collections.emptyList());
            assertThat(creds, hasSize(1));
            assertThat(creds.get(0).getDescription(), is("my creds"));
            assertThat("private key rotated by resaving", creds.get(0).publicKey().getModulus(), is(not(modulus.get())));
        });
    }

}
