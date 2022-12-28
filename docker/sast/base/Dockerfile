FROM debian:buster-slim
#   Copyright 2018-2021 getcarrier.io
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
LABEL author="artem_rozumenko@epam.com"
LABEL updated.by="ivan_krakhmaliuk@epam.com"

# Core software and tools versions
ARG GOLANG_VERSION=1.14.2
ARG NODEJS_VERSION=14

# SAST software and tools versions: python
ARG BANDIT_VERSION=1.6.2
ARG SAFETY_VERSION=1.9.0

# SAST software and tools versions: golang
ARG GOSEC_VERSION=2.3.0

# SAST software and tools versions: nodejs
ARG NODEJSSCAN_VERSION=3.7
ARG RETIRE_VERSION=2.2.1
ARG YARN_VERSION=1.22.10

# SAST software and tools versions: ruby
ARG BRAKEMAN_VERSION=4.8.1

# SAST software and tools versions: java
ARG FINDSECBUGS_VERSION=1.10.1

# SAST software and tools versions
ARG GITLEAKS_VERSION=8.15.2
ARG DEPENDENCY_CHECK_VERSION=7.4.2
ARG INSIDER_VERSION=2.0.5
ARG SEMGREP_VERSION=1.2.1
ARG TRIVY_VERSION=0.35.0
ARG SECURITY_SCAN_VERSION=5.2.2

# Default locale
ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8

# Core: Python
RUN set -x \
  && apt-get update \
  && apt-get install --no-install-recommends -y \
      ca-certificates curl \
      python3 python3-dev \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/* \
  && curl -sL https://bootstrap.pypa.io/get-pip.py | python3 - \
  && pip3 --version

# Core: Golang
ENV GOPATH=/go
ENV PATH=$GOPATH/bin:/usr/local/go/bin:$PATH
RUN set -x \
  && curl -sL https://golang.org/dl/go${GOLANG_VERSION}.linux-amd64.tar.gz | tar -C /usr/local -xzvf - \
  && mkdir -p "$GOPATH/src" "$GOPATH/bin" \
  && chmod -R 777 "$GOPATH" \
  && go version

# Core: NodeJS
RUN set -x \
  && curl -sL https://deb.nodesource.com/setup_${NODEJS_VERSION}.x | bash - \
  && apt-get update \
  && apt-get install --no-install-recommends -y nodejs \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

# Core: Ruby
RUN set -x \
  && apt-get update \
  && apt-get install --no-install-recommends -y ruby \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

# Core: Java
RUN set -x \
  && mkdir -p /usr/share/man/man1 \
  && apt-get update \
  && apt-get install --no-install-recommends -y default-jre-headless ca-certificates-java \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

# Core: Dotnet Core
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1
RUN set -x \
  && curl -sL https://packages.microsoft.com/config/debian/10/packages-microsoft-prod.deb -o packages-microsoft-prod.deb \
  && dpkg -i packages-microsoft-prod.deb \
  && rm packages-microsoft-prod.deb \
  && apt-get update \
  && apt-get install --no-install-recommends -y dotnet-sdk-5.0 \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

# SAST: pybandit (Python SAST tool)
RUN set -x \
  && pip3 install --no-cache-dir --disable-pip-version-check bandit==${BANDIT_VERSION}

# SAST: safety (Python SAST composition analysis tool)
RUN set -x \
  && pip3 install --no-cache-dir --disable-pip-version-check safety==${SAFETY_VERSION}

# SAST: gosec (Golang Security Checker)
RUN set -x \
  && curl -sL https://github.com/securego/gosec/releases/download/v${GOSEC_VERSION}/gosec_${GOSEC_VERSION}_linux_amd64.tar.gz | tar -C /usr/local/bin -xzvf - \
  && gosec --version

# SAST: NodeJsScan
RUN set -x \
  && pip3 install --no-cache-dir --disable-pip-version-check nodejsscan==${NODEJSSCAN_VERSION}

# SAST: retirejs
RUN set -x \
  && npm install -g retire@${RETIRE_VERSION}

# SAST: yarn for depcheck and other scanners reading yarn.lock
RUN set -x \
  && npm install -g yarn@${YARN_VERSION}

# SAST: brakeman (Ruby SAST tool)
RUN set -x \
  && gem install brakeman -v ${BRAKEMAN_VERSION} \
  && brakeman --version

# SAST: FindSecBugs
RUN set -x \
  && apt-get update \
  && apt-get install --no-install-recommends -y unzip \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/* \
  && mkdir -p /opt/findsecbugs-${FINDSECBUGS_VERSION} \
  && cd /opt/findsecbugs-${FINDSECBUGS_VERSION} \
  && curl -LOJ https://github.com/find-sec-bugs/find-sec-bugs/releases/download/version-${FINDSECBUGS_VERSION}/findsecbugs-cli-${FINDSECBUGS_VERSION}.zip \
  && unzip findsecbugs-cli-${FINDSECBUGS_VERSION}.zip \
  && rm -f findsecbugs-cli-${FINDSECBUGS_VERSION}.zip \
  && chmod a+x /opt/findsecbugs-${FINDSECBUGS_VERSION}/*.sh \
  && find /opt/findsecbugs-${FINDSECBUGS_VERSION} -type f -iname '*.sh' -maxdepth 1 -printf 'update-alternatives --install /usr/bin/%f %f %p 9999\n' | bash \
  && update-alternatives --install /usr/bin/spotbugs spotbugs /usr/bin/findsecbugs.sh 9999

# SAST: gitleaks
RUN set -x \
  && curl -sL https://github.com/zricethezav/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz | tar -C /usr/local/bin -xzvf - \
  && gitleaks --version

# SAST: Dependency Check
RUN set -x \
  && cd /opt \
  && curl -sL https://github.com/jeremylong/DependencyCheck/releases/download/v${DEPENDENCY_CHECK_VERSION}/dependency-check-${DEPENDENCY_CHECK_VERSION}-release.zip -o dependency-check-${DEPENDENCY_CHECK_VERSION}-release.zip \
  && unzip dependency-check-${DEPENDENCY_CHECK_VERSION}-release.zip \
  && rm -rf dependency-check-${DEPENDENCY_CHECK_VERSION}-release.zip \
  && chmod a+x /opt/dependency-check/bin/*.sh \
  && find /opt/dependency-check/bin/ -type f -iname '*.sh' -maxdepth 1 -printf 'update-alternatives --install /usr/bin/%f %f %p 9999\n' | bash \
  && dependency-check.sh --updateonly \
  && chmod -R 777 /opt/dependency-check/data \
  && ls -al /opt/dependency-check/data

# SAST: insider
RUN set -x \
  && curl -sL https://github.com/insidersec/insider/releases/download/${INSIDER_VERSION}/insider_${INSIDER_VERSION}_linux_x86_64.tar.gz | tar -C /usr/local/bin -xzvf -

# SAST: semgrep
RUN set -x \
  && pip3 install --no-cache-dir --disable-pip-version-check semgrep==${SEMGREP_VERSION} \
  && mkdir -p /opt/semgrep/rulesets \
  && curl -sL https://semgrep.dev/c/p/findsecbugs -o /opt/semgrep/rulesets/findsecbugs.yml \
  && curl -sL https://semgrep.dev/c/p/r2c-CI -o /opt/semgrep/rulesets/r2c-CI.yml \
  && curl -sL https://semgrep.dev/c/p/r2c-security-audit -o /opt/semgrep/rulesets/r2c-security-audit.yml

# SAST: trivy
RUN set -x \
  && curl -sL https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz | tar -C /usr/local/bin -xzvf - \
  && trivy image --download-db-only

# SAST: Security Code Scan
RUN set -x \
  && dotnet tool install security-scan --version ${SECURITY_SCAN_VERSION} --tool-path /usr/local/bin

# Legacy module depencies (will be removed as soon as all external modules adapted)
RUN set -x \
  && pip3 install lxml==4.2.5

# Dusty depencies
RUN set -x \
  && apt-get update \
  && apt-get install --no-install-recommends -y \
    libpq-dev \
    git \
    build-essential \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

# Resolver depencies
RUN set -x \
  && apt-get update \
  && apt-get install --no-install-recommends -y maven \
  && apt-get install --no-install-recommends -y gradle \
  && apt-get install --no-install-recommends -y ant \
  && apt-get install --no-install-recommends -y ivy \
  && apt-get install --no-install-recommends -y nuget \
  && npm install -g lerna \
  && npm install -g bower \
  && pip3 install virtualenv pipdeptree \
  && apt-get install --no-install-recommends -y php-cli php-curl composer \
  && curl -sL https://github.com/sbt/sbt/releases/download/v1.5.6/sbt-1.5.6.tgz | tar -C /opt -xzvf - \
  && update-alternatives --install /usr/bin/sbt sbt /opt/sbt/bin/sbt 9999 \
  && curl -sL https://swift.org/builds/swift-5.3.3-release/ubuntu1804/swift-5.3.3-RELEASE/swift-5.3.3-RELEASE-ubuntu18.04.tar.gz | tar -C /opt -xzvf - \
  && find /opt/swift-5.3.3-RELEASE-ubuntu18.04/usr/bin/ -maxdepth 1 -type f,l -printf 'update-alternatives --install /usr/bin/%f %f %p 9999\n' | bash \
  && apt-get install --no-install-recommends -y ruby-full \
  && apt-get install --no-install-recommends -y ruby ruby-dev make gcc libcurl4 libc6-dev git \
  && gem install cocoapods -v '< 1.11' \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*
