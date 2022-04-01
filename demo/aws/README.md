Allows Jenkins running locally to authenticate to AWS and access an S3 bucket.
A GCS bucket is used as the identity provider.

Tools required beyond typical Linux commands:
* `mvn` (thus also `java`)
* `docker`
* `aws` (preconfigured with an account to which you have reasonable access)
* `gsutil` (comes with `gcloud`) (ditto)
* `jq`
* `openssl`

Run:

```bash
bash run.sh
```

and note the message about a cleanup script.
