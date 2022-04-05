Allows Jenkins running in GKE to authenticate to AWS and access an S3 bucket.

Tools required beyond typical Linux commands:
* `helm`
* `kubectl`
* `aws` (preconfigured with an account to which you have reasonable access)
* `gcloud` (ditto)
* `jq`
* `openssl`

Run:

```bash
bash run.sh
```

and note the message about a cleanup script.
