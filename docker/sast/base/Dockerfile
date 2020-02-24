FROM ubuntu:xenial
#   Copyright 2018-2019 getcarrier.io
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

# Software versions
ARG JAVA_OPENJDK_URL=https://download.java.net/java/GA/jdk10/10.0.2/19aef61b38124481863b1413dce1855f/13/openjdk-10.0.2_linux-x64_bin.tar.gz
ARG JAVA_OPENJDK_VERSION=10.0.2
ARG RUBY_VERSION=2.3.0-dev
ARG GOLANG_VERSION=1.12.4

# SAST tool versions
ARG BANDIT_VERSION=1.5.1
ARG SPOTBUGS_VERSION=3.1.12
ARG FINDSECBUGS_VERSION=1.8.0
ARG DEPENDENCY_CHECK_VERSION=5.2.1
ARG GITLEAKS_VERSION=2.1.0

# Default locale
ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8

# Base software package
RUN set -x \
  && apt-get update \
  && apt-get install --no-install-recommends -y \
    software-properties-common apt-transport-https ca-certificates curl gnupg2 wget \
  && add-apt-repository ppa:jonathonf/python-3.6 \
  && apt-get update \
  && apt-get install --no-install-recommends -y \
    default-jre default-jdk xvfb git gcc make \
    build-essential libssl-dev zlib1g-dev libbz2-dev libpcap-dev unzip \
    libreadline-dev libsqlite3-dev llvm libncurses5-dev libncursesw5-dev \
    xz-utils tk-dev libffi-dev liblzma-dev perl libnet-ssleay-perl python-dev python-pip \
    libxslt1-dev libxml2-dev libyaml-dev openssh-server  python-lxml \
    xdot python-gtk2 python-gtksourceview2 dmz-cursor-theme supervisor \
    python-setuptools maven python3.6 python3.6-dev \
    virtualenv python-virtualenv python3-virtualenv checkinstall \
    autoconf bison libreadline6-dev libgdbm3 libgdbm-dev \
    rbenv ruby-build \
    libpq-dev \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

# Docker
RUN set -x \
  && curl -fsSL https://download.docker.com/linux/debian/gpg | apt-key add - \
  && apt-key fingerprint 0EBFCD88 \
  && echo "deb [arch=amd64] https://download.docker.com/linux/debian stretch stable" | \
	 tee /etc/apt/sources.list.d/docker.list \
  && apt-get update \
  && apt-get install --no-install-recommends -y docker-ce \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

# Java
RUN set -x \
  && cd /opt \
  && wget -qO- ${JAVA_OPENJDK_URL} | tar vxfz - \
  && find /opt/jdk-${JAVA_OPENJDK_VERSION}/bin/ -type f -printf 'update-alternatives --install /usr/bin/%f %f %p 9999\n' | bash

# Ruby
RUN set -x \
  && cd /tmp \
  && rbenv install ${RUBY_VERSION} \
  && rbenv global ${RUBY_VERSION} \
  && rm -rf /tmp/ruby-*

# NodeJS
RUN set -x \
  && curl -sL https://deb.nodesource.com/setup_10.x | bash - \
  && apt-get update \
  && apt-get install --no-install-recommends -y nodejs \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/* \
  && npm -g i n && n 10.13.0 --test && npm -g i npm@6.1 http-server@0.11.1 retire@1.6.0 --test \
  && rm -rf /tmp/npm-*

# Python
RUN set -x \
  && update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.6 9999 \
  && curl -sL https://bootstrap.pypa.io/get-pip.py | python3 - \
  && pip3 install --upgrade pip wheel setuptools \
  && curl -sL https://bootstrap.pypa.io/get-pip.py | python2 - \
  && pip2 install --upgrade pip wheel setuptools \
  && pip --version \
  && pip2 --version \
  && pip3 --version

# Golang
ENV GOPATH=/go
ENV PATH=$GOPATH/bin:/usr/local/go/bin:$PATH
RUN set -x \
  && wget -qO- https://golang.org/dl/go${GOLANG_VERSION}.linux-amd64.tar.gz | tar -C /usr/local -xzvf - \
  && mkdir -p "$GOPATH/src" "$GOPATH/bin" \
  && chmod -R 777 "$GOPATH" \
  && go version

# Dotnet Core
RUN set -x \
  && wget -q https://packages.microsoft.com/config/ubuntu/16.04/packages-microsoft-prod.deb -O packages-microsoft-prod.deb \
  && dpkg -i packages-microsoft-prod.deb \
  && rm packages-microsoft-prod.deb \
  && apt-get update \
  && apt-get install --no-install-recommends -y dotnet-sdk-2.2 \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

# SAST: pybandit (Python SAST tool)
RUN set -x \
  && pip3 install bandit==${BANDIT_VERSION}

# SAST: safety (Python SAST composition analysis tool)
RUN set -x \
  && pip3 install safety

# SAST: Spotbugs
RUN set -x \
  && cd /opt \
  && curl -LOJ http://repo.maven.apache.org/maven2/com/github/spotbugs/spotbugs/${SPOTBUGS_VERSION}/spotbugs-${SPOTBUGS_VERSION}.zip \
  && unzip spotbugs-${SPOTBUGS_VERSION}.zip \
  && rm -rf spotbugs-${SPOTBUGS_VERSION}.zip \
  && cd /opt/spotbugs-${SPOTBUGS_VERSION}/plugin \
  && curl -LOJ https://search.maven.org/remotecontent?filepath=com/h3xstream/findsecbugs/findsecbugs-plugin/${FINDSECBUGS_VERSION}/findsecbugs-plugin-${FINDSECBUGS_VERSION}.jar \
  && cd ../.. \
  && find /opt/spotbugs-${SPOTBUGS_VERSION}/bin/ -type f -maxdepth 1 -printf 'update-alternatives --install /usr/bin/%f %f %p 9999\n' | bash

# SAST: Dependency Check
RUN set -x \
  && cd /opt \
  && curl -LOJ  https://bintray.com/jeremy-long/owasp/download_file?file_path=dependency-check-${DEPENDENCY_CHECK_VERSION}-release.zip \
  && unzip dependency-check-${DEPENDENCY_CHECK_VERSION}-release.zip \
  && rm -rf dependency-check-${DEPENDENCY_CHECK_VERSION}-release.zip \
  && find /opt/dependency-check/bin/ -type f -maxdepth 1 -printf 'update-alternatives --install /usr/bin/%f %f %p 9999\n' | bash \
  && dependency-check.sh --updateonly \
  && chmod -R 777 /opt/dependency-check/data \
  && ls -al /opt/dependency-check/data

# SAST: NodeJsScan
RUN set -x \
  && pip3 install nodejsscan

# SAST: bakeman (Ruby SAST tool)
RUN set -x \
  && gem install brakeman

# SAST: gosec (Golang Security Checker)
RUN set -x \
  && go get github.com/securego/gosec/cmd/gosec \
  && rm -rf $GOPATH/src/*

# SAST: gitleaks
RUN set -x \
  && wget https://github.com/zricethezav/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks-linux-amd64 -O /usr/local/bin/gitleaks \
  && chmod a+x /usr/local/bin/gitleaks
