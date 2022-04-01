FROM jenkins/jenkins:lts

USER root

RUN curl https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip -o /tmp/aws-cli.zip && \
	cd /tmp && \
	unzip aws-cli.zip && \
	./aws/install && \
	aws --version

RUN cd /tmp && \
	curl -sL https://dl.step.sm/gh-release/cli/gh-release-header/v0.18.2/step_linux_0.18.2_amd64.tar.gz | tar xvfz - && \
	mv */bin/step /usr/local/bin && \
	step certificate inspect https://smallstep.com

ADD jenkins-home /usr/share/jenkins/ref
RUN chown -R jenkins.jenkins /usr/share/jenkins/ref

USER jenkins

ENV JAVA_OPTS=-Dhudson.Main.development=true
