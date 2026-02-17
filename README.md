# OpenID Connect Provider Plugin

## Introduction

This plugin allows Jenkins builds to be issued “id tokens” in a JSON Web Token (JWT) format
according to OpenID Connect (OIDC) Discovery conventions.
The purpose is to permit Jenkins to authenticate keylessly to external systems such as AWS or GCP.

For example, if you wished to access GCP services (such as to deploy to Cloud Run),
you could create a long-lived static service account key and store this secret inside Jenkins.
But anyone who manages to steal the secret value could quietly access GCP on their own,
so you would need to periodically rotate the secret and institute special controls over its usage.
Some organizations may even prohibit you from creating such static keys at all.

Or if Jenkins itself were running on GCP (say in a GKE cluster),
you could configure “workload identity” so that the Jenkins agent process is preauthenticated
to be able to use a specific service account.
This is more secure and manageable.
It only works within the one vendor, however.

Using OIDC, you can instead rely on what is sometimes referred to as “web identity federation”.
Rather than a secret value, what the external service trusts is that
the Jenkins administrator is in control over what is served from the known (HTTPS) URL.
Internally Jenkins maintains an asymmetric cryptographic keypair.
Builds receive a temporary (timestamped) id token signed with the private key;
Jenkins serves the public key (anonymously) for anyone to verify the authenticity of the tokens.
The service might trust any token from Jenkins,
or might match specific “claims” such as the identity of the project or Git branch name.

As a special case, the service being accessed may in fact be a secret store such as Vault or Conjur.
Then the Jenkins build can use its id token to access the secret store and retrieve a secret,
which _then_ can be used to access something else
such as a database which only supports traditional passwords.
The advantage is that the database password need not be stored in the Jenkins controller
(it would only be used transiently by an agent process),
so administrators can apply audit controls, rotation policies, etc. in a full-featured storage service.

The [Conjur Secrets plugin](https://plugins.jenkins.io/conjur-credentials/)
uses a similar system, tailored specifically to Conjur.
The [OpenId Connect Authentication plugin](https://plugins.jenkins.io/oic-auth/)
allows OIDC to be used to authenticate users _to_ Jenkins and is completely unrelated to this use case.

## Configuring

Setting up keyless authentication requires a few steps.

### Picking an issuer

First, decide what the “issuer” of the tokens should be.
By default, Jenkins itself will issue tokens.
This is appropriate if it served from an HTTPS URL visible to the Internet
(or at least the relevant vendor service).

If the service cannot physically access Jenkins,
you may instead designate another issuer URI.
In this case you must find a way to host two small, static JSON files under that URL.
Jenkins will still sign id tokens with its private key;
the public key, which does not normally change, gets served by the alternate issuer.
(The `iss` claim in the id token will also be updated to match.)

### Creating Jenkins credentials

In Jenkins, create one of two types of credentials:
* **OpenID Connect id token** (yields the id token directly as “secret text”)
* **OpenID Connect id token as file** (saves the id token to a temporary file and yields its path)

The credentials id is recommended for scripted access in your pipelines, or you may let one be chosen at random.
You may enter an audience URI at this time (see below) but it is optional.

The credential may be created at the Jenkins root, or in a folder. If you leave the field empty, it will create
the credential at the root, typically under the URI `https://YOUR_JENKINS_HOST/oidc`
After saving, click on the **Update** Link to see the generated issuer URI.
If you picked the external issuer option or entered any value in the issuer URI field,
you will be given instructions on what static files to serve from it and their values.

To rotate the keypair, simply **Update** and re-**Save** (or otherwise recreate) the credentials.

### Registering the identity provider

Refer to service-specific documentation for creating an “identity provider” or “pool” etc.
You will need to enter at least the issuer URI.
You may ask the service to recognize a particular “audience” URI,
or the service may specify an audience you should use.
The service may allow authorization decisions to be made based on various claims:
the `iss` (issuer),
the `aud` (audience),
the `sub` (subject—in this context, by default the URL of a Jenkins job),
or others (currently a Jenkins build number is included by default).

The service may associate an identity provider with a service account, role, etc.
This is normally how specific privileges for specific objects are granted.

### Use id tokens from builds

When the id token credentials are accessed during a build
(typically via the [Credentials Binding plugin](https://plugins.jenkins.io/credentials-binding/)),
Jenkins will generate a fresh id token scoped to that build with a limited validity.
Refer to service-specific documentation to see how the token can be used to authenticate.

### Configuring claims

If the default claims are not sufficient, you can customize them.
Go to **Manage Jenkins** » **Configure Global Security**
and under **OpenID Connect** edit the **Claim templates…** to your liking.

Each template represent a claim (JSON property) to be set in id tokens.
You must include at least <code>sub</code> (subject) in the list.
The value may be a fixed string, or it may be use substitutions from build variables.
For example, `jenkins:${BRANCH_NAME}:${BUILD_NUMBER}` might expand to `jenkins:master:123`.
Normally the claim will be set to a **string** but you may choose a **boolean** (`true` or `false`)
or an **integer** if you prefer these types in the JWT.

You can add claims to all id tokens, those used during builds,
or those used outside of builds (for example by other Jenkins plugins accepting string credentials).
All applicable kinds of claim templates will be merged.

### Using SCM information in claims

If your build uses Git SCM (Source Code Management), you can include Git-related information in your id token claims.
The following variables are available:

* `${GIT_URL}` - The URL of the Git repository (e.g., `https://github.com/user/repo.git`)
* `${GIT_BRANCH}` - The branch reference being built (e.g., `origin/master`, `upstream/main`, or `master`)
* `${GIT_COMMIT}` - The commit SHA being built (e.g., `abc123def456...`)

These variables can be used in claim templates, for example:

```
git_repository: ${GIT_URL}
git_branch: ${GIT_BRANCH}
git_sha: ${GIT_COMMIT}
```

**How it works:**

* Git information is extracted from `BuildData` actions created by the Git plugin during checkout
* For **Declarative Pipeline jobs**: Git checkout happens automatically before stages, so variables are available immediately
* For **Scripted Pipeline jobs**: Use explicit `checkout scm` before calling `withCredentials`
* For **Freestyle jobs**: Git checkout in build step populates `BuildData` automatically

## Examples

Some tested usage examples follow. Please contribute others!

### Accessing AWS

You will need to create a web identity federation provider,
including a role with a trust policy offering `sts:AssumeRoleWithWebIdentity`
and a permissions policy granting specific abilities.
The audience should conventionally be `sts.amazonaws.com`.
AWS requires the TLS certificate fingerprint of the issuer to be saved.

Here is an example of such trust policy with account `1234567890` and Jenkins instance running on `https://jenkins.acme.com/`, using the default issuer URL, restricting access to a job named `my-job`:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Federated": "arn:aws:iam::1234567890:oidc-provider/jenkins.acme.com/oidc"
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "jenkins.acme.com/oidc:aud": "sts.amazonaws.com",
                    "jenkins.acme.com/oidc:sub": "https://jenkins.acme.com/job/my-job/"
                }
            }
        }
    ]
}
```

If you set the environment variable `AWS_ROLE_ARN`
and bind `AWS_WEB_IDENTITY_TOKEN_FILE` to a temporary file containing an id token,
you can run `aws` CLI commands without further ado.
Every time the role is assumed, AWS contacts the issuer to retrieve the public key.

A fully automated, end-to-end demo is available.
This also demonstrates configuration of Jenkins as code.
See [instructions](demo/aws/README.md).

### Accessing GCP

You will create a workload identity pool and bind it to a service account
(which should have already been created with the desired permissions).
Sketch of setup:

```bash
ISSUER=https://jenkins/oidc
PROJECT=12345678
POOL=your-pool-name
PROVIDER=static
SA=some-sa@your-project.iam.gserviceaccount.com
gcloud iam workload-identity-pools create $POOL \
  --location=global
gcloud iam workload-identity-pools providers create-oidc $PROVIDER \
  --workload-identity-pool=$POOL \
  --issuer-uri=$ISSUER \
  --location=global \
  --attribute-mapping=google.subject=assertion.sub
gcloud iam service-accounts add-iam-policy-binding $SA \
  --role=roles/iam.workloadIdentityUser \
  --member="principalSet://iam.googleapis.com/projects/$PROJECT/locations/global/workloadIdentityPools/$POOL/*"
echo audience must be https://iam.googleapis.com/projects/$PROJECT/locations/global/workloadIdentityPools/$POOL/providers/$PROVIDER
```

Using the id token is currently more awkward than from AWS, unfortunately.
Sketch of usage from a build:

```groovy
withCredentials([file(variable: 'ID_TOKEN_FILE', credentialsId: 'gcp')]) {
  writeFile file: "$WORKSPACE_TMP/creds.json", text: """
    {
      "type": "external_account",
      "audience": "//iam.googleapis.com/projects/12345678/locations/global/workloadIdentityPools/your-pool-name/providers/static",
      "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
      "token_url": "https://sts.googleapis.com/v1/token",
      "service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/some-sa@your-project.iam.gserviceaccount.com:generateAccessToken",
      "credential_source": {
        "file": "$ID_TOKEN_FILE",
        "format": {
          "type": "text"
        }
      }
    }
  """
  sh '''
    gcloud auth login --brief --cred-file=$WORKSPACE_TMP/creds.json
    gcloud --project your-project run deploy …
  '''
}
```

GCP contacts the issuer periodically (every few minutes) to retrieve the public key,
whether or not the pool is in use.
(Your access log will show the user agent as `google-thirdparty-credentials`.)
GCP seems to tolerate any TLS certificate that can validate against a root chain.

### Accessing HashiCorp Vault

You will enable and configure `jwt` authentication and use a role for a specific pipeline job.
This way access to required secrets can be granted on a job level.
The pipeline will exchange the JWT against a Vault token and then use that token to access a secret.
In this example the ID token (JWT) credential will be created in a folder.

Assume there is a kv v2 secret `my-secret` with the secret engine mounted at `kv` and a policy
`my-policy` granting read capability to this secret.

In Jenkins, in folder `oidc-folder`, create an `OpenID Connect id token` credential with ID `id-token`.
Copy the `Issuer URI`.

In the same folder, create a pipeline job `oidc-job`:

```groovy
pipeline {
  agent {
    kubernetes {
      yaml '''
        apiVersion: v1
        kind: Pod
        spec:
          containers:
          - name: vault
            image: hashicorp/vault
            command:
            - cat
            tty: true
      '''
    }
  }

  stages {
    stage('vault') {
      environment {
        VAULT_ADDR="<Vault API server address>"
        VAULT_NAMESPACE="<only for Vault Enterprise / HCP, remove otherwise>"
      }
      steps {
        withCredentials([string(credentialsId: 'id-token', variable: 'IDTOKEN')]) {
          container('vault') {
            sh 'vault write -field=token auth/jwt/login jwt=${IDTOKEN} > token'
            sh 'set +x ; VAULT_TOKEN=$(cat token) vault read -field=data -format=json kv/data/my-secret'
          }
        }
      }
    }
  }
}
```

Configure Vault:
```bash
vault auth enable jwt
vault write auth/jwt/role/my-role name=my-role role_type=jwt policies=my-policy \
    bound_subject="https://jenkins/job/oidc-folder/job/oidc-job/" user_claim=sub
vault write auth/jwt/config oidc_discovery_url="<Issuer URI>" \
    bound_issuer="<Issuer URI>" default_role=my-role
```

## References

Some relevant background reading. Not intended to be exhaustive.

### AWS

* [About web identity federation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_oidc.html)

### GCP

* [Introductory video](https://youtu.be/4vajaXzHN08)
* [Workload identity federation](https://cloud.google.com/iam/docs/workload-identity-federation) (introduction)
* [Access resources from an OIDC identity provider](https://cloud.google.com/iam/docs/configuring-workload-identity-federation#oidc) (detailed guide)

### Security considerations

* [Tweet re: workload identity vs. “sops”](https://twitter.com/lorenc_dan/status/1420188842703958020) (from a founder/CEO of Chainguard, active in supply-chain security)
* [Article on Codecov credentials leak](https://www.theregister.com/2021/04/19/codecov_warns_of_stolen_credentials/)

### Analogous features in other CI systems

* [GitHub Actions: Secure cloud deployments with OpenID Connect](https://github.blog/changelog/2021-10-27-github-actions-secure-cloud-deployments-with-openid-connect/)
* [Connecting Bitbucket to resources via OIDC](https://support.atlassian.com/bitbucket-cloud/docs/integrate-pipelines-with-resource-servers-using-oidc/)
* [Connecting GitLab to Vault via OIDC](https://docs.gitlab.com/ee/ci/examples/authenticating-with-hashicorp-vault/)

### Secret stores accessible ultimately via OIDC

* [AWS](https://aws.amazon.com/secrets-manager/)
* [GCP](https://cloud.google.com/secret-manager)
* [CyberArk Conjur: OIDC Authenticator](https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/OIDC/OIDC.htm)
* [Using JWT/OIDC from Vault](https://www.vaultproject.io/docs/auth/jwt)

## LICENSE

Licensed under MIT, see [LICENSE](LICENSE.md)
