#!/bin/bash
set -euxo pipefail
cd $(dirname "$0")

name=demo-$USER-$RANDOM
echo set -euxo pipefail >/tmp/cleanup-$name.sh
trap "echo '====>' To clean up: bash /tmp/cleanup-$name.sh" EXIT

aws s3api create-bucket --bucket $name
echo "aws s3 rb --force s3://$name" >>/tmp/cleanup-$name.sh

gcloud container clusters create $name \
	--machine-type=n1-standard-4 \
	--cluster-version=latest
echo "gcloud -q container clusters delete $name" >>/tmp/cleanup-$name.sh

helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
helm repo add jetstack https://charts.jetstack.io
helm repo add jenkins https://charts.jenkins.io
helm repo update

helm install \
	--wait \
	--namespace ingress-nginx \
	--create-namespace \
	--set controller.ingressClass=nginx \
	--set controller.service.externalTrafficPolicy=Local \
	--version 4.0.18 \
	ingress-nginx \
	ingress-nginx/ingress-nginx
extip=
while [ -z "$extip" ]
do
	extip=`kubectl get svc --namespace ingress-nginx ingress-nginx-controller -o jsonpath='{.status.loadBalancer.ingress[0].ip}'`
	echo waiting for ingress to be ready
	sleep 3
done
host=$name.$extip.nip.io

helm install --wait \
	--namespace cert-manager --create-namespace \
	--set installCRDs=true \
	--version v1.7.1 \
	cert-manager \
	jetstack/cert-manager

kubectl create namespace jenkins
kubectl config set-context --current --namespace=jenkins

kubectl apply -f - <<YAML
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: self-signed
spec:
  selfSigned: {}
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: jenkins
spec:
  secretName: jenkins-tls
  dnsNames:
  - $host
  # https://github.com/cert-manager/cert-manager/issues/3634#issuecomment-774292453
  commonName: what.ever
  issuerRef:
    name: self-signed
YAML
until kubectl get secret jenkins-tls
do
	sleep 5
done

provider_arn=$(aws iam create-open-id-connect-provider \
	--url https://$host/oidc \
	--client-id-list sts.amazonaws.com \
	--thumbprint-list $(kubectl get -o json secret jenkins-tls | jq -r '.data["ca.crt"]' | base64 -d | openssl x509 -fingerprint -noout | cut -d= -f2 | tr -d :) \
	| jq -r .OpenIDConnectProviderArn)
echo "aws iam delete-open-id-connect-provider --open-id-connect-provider-arn $provider_arn" >>/tmp/cleanup-$name.sh

cat >/tmp/trust-policy.json <<JSON
{
  "Version": "2012-10-17",
  "Statement": {
    "Effect": "Allow",
    "Principal": {
      "Federated": "$provider_arn"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "$host/oidc:sub": "https://$host/job/use-oidc/"
      }
    }
  }
}
JSON
aws iam create-role --role-name $name --assume-role-policy-document file:///tmp/trust-policy.json
cat >/tmp/permissions-policy.json <<JSON
{
  "Version": "2012-10-17",
  "Statement": {
    "Effect": "Allow",
    "Action": [
      "s3:ListBucket",
      "s3:PutObject"
    ],
    "Resource": [
      "arn:aws:s3:::$name",
      "arn:aws:s3:::$name/*"
    ]
  }
}
JSON
aws iam put-role-policy --role-name $name --policy-name permissions --policy-document file:///tmp/permissions-policy.json
(echo "aws iam delete-role-policy --role-name $name --policy-name permissions"; echo "aws iam delete-role --role-name $name") >>/tmp/cleanup-$name.sh

cat >/tmp/jenkins.yaml <<YAML
controller:
  ingress:
    enabled: true
    apiVersion: networking.k8s.io/v1
    hostName: $host
    ingressClassName: nginx
    tls:
    - secretName: jenkins-tls
  additionalPlugins:
  - job-dsl
  - oidc-provider
  - timestamper
  JCasC:
    configScripts:
      demo: |
        credentials:
          system:
            domainCredentials:
            - credentials:
              - idTokenFile:
                  id: aws-jwt
                  scope: GLOBAL
                  audience: sts.amazonaws.com
        unclassified:
          timestamper:
            allPipelines: true
        jobs:
        - script: |
            pipelineJob('use-oidc') {
              definition {
                cps {
                  script('''
                    pipeline {
                      environment {
                        AWS_ROLE_ARN = '$(aws iam get-role --role-name=$name --output text --query Role.Arn)'
                        AWS_WEB_IDENTITY_TOKEN_FILE = credentials('aws-jwt')
                      }
                      agent {
                        label 'demo'
                      }
                      stages {
                        stage('Diagnostics') {
                          steps {
                            sh 'sed "s/[.]/../g" < \$AWS_WEB_IDENTITY_TOKEN_FILE'
                            container('step') {
                              sh 'step crypto jwt inspect --insecure < \$AWS_WEB_IDENTITY_TOKEN_FILE'
                            }
                            container('awscli') {
                              sh 'aws sts get-caller-identity'
                            }
                          }
                        }
                        stage('Work') {
                          steps {
                            container('awscli') {
                              sh 'date | aws s3 cp - s3://$name/\$BUILD_TAG.txt && aws s3 ls s3://$name'
                            }
                          }
                        }
                      }
                    }'''.stripIndent().trim())
                    sandbox()
                }
              }
            }
agent:
  podTemplates:
    demo: |
      - name: demo
        label: demo
        containers:
        - name: step
          image: smallstep/step-cli
          command: sleep
          args: '999999'
        - name: awscli
          image: amazon/aws-cli
          command: sleep
          args: '999999'
YAML
helm install --wait \
	--values /tmp/jenkins.yaml \
	jenkins \
	jenkins/jenkins
echo 'You will be able to log in as user admin with this password (accept the self-signed certificate):'
kubectl exec sts/jenkins -- cat /run/secrets/chart-admin-password && echo
echo "Now try running: https://$host/job/use-oidc/"
