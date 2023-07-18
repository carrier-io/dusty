FROM debian:buster-backports
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
ARG NODEJS_VERSION=14

# DAST software and tools versions
ARG AEMHACKER_VERSION=3ce91f217b259b0b4e6abd07f56d453b0c82b46b
ARG MASSCAN_VERSION=9065684c52682d3e12a35559ef72cd0f07838bff
ARG NIKTO_VERSION=06137391fdd4450de9ea4023ed245b85ed972c28
ARG NMAP_VERSION=7.94
ARG SSLYZE_VERSION=5.1.3
# ARG W3AF_VERSION=cd22e5252243a87aaa6d0ddea47cf58dacfe00a9
ARG W3AF_VERSION=8ef1c7cdb92ef4efb369848991085ccb98762a58
ARG ZAP_VERSION=2.13.0

# Default locale
ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8

# Core: System
RUN set -x \
  && apt-get update \
  && apt-get install --no-install-recommends -y \
      dos2unix procps \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

# Core: Python
RUN set -x \
  && apt-get update \
  && apt-get install --no-install-recommends -y \
      ca-certificates curl \
      python python-dev \
      python3 python3-dev \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/* \
  && curl -sL https://bootstrap.pypa.io/get-pip.py | python3 - \
  && curl -sL https://bootstrap.pypa.io/pip/2.7/get-pip.py | python - \
  && pip3 --version \
  && pip2 --version \
  && pip --version

# Core: NodeJS
RUN set -x \
  && curl -sL https://deb.nodesource.com/setup_${NODEJS_VERSION}.x | bash - \
  && apt-get update \
  && apt-get install --no-install-recommends -y nodejs \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

# Core: Java
RUN set -x \
  && apt-get update \
  && apt-get install --no-install-recommends -y default-jre-headless ca-certificates-java \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

# DAST: AEM Hacker
RUN set -x \
  && apt-get update \
  && apt-get install --no-install-recommends -y git \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/* \
  && cd /opt \
  && git clone https://github.com/0ang3el/aem-hacker.git \
  && cd aem-hacker \
  && git reset --hard ${AEMHACKER_VERSION} \
  && pip3 install --upgrade -r requirements.txt \
  && echo '#!/bin/bash' > /opt/aem-hacker/aem-wrapper.sh \
  && echo 'python3 /opt/aem-hacker/aem_hacker.py $*' >> /opt/aem-hacker/aem-wrapper.sh \
  && chmod a+x *.py *.sh \
  && rm -rf .git \
  && cd .. \
  && update-alternatives --install /usr/bin/aem-wrapper.sh aem-wrapper.sh /opt/aem-hacker/aem-wrapper.sh 9999

# DAST: Masscan
RUN set -x \
  && apt-get update \
  && apt-get install --no-install-recommends -y build-essential libpcap-dev \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/* \
  && cd /opt \
  && git clone https://github.com/robertdavidgraham/masscan \
  && cd masscan \
  && git reset --hard ${MASSCAN_VERSION} \
  && make -j4 \
  && rm -rf .git \
  && update-alternatives --install /usr/bin/masscan masscan /opt/masscan/bin/masscan 9999

# DAST: Nikto
RUN set -x \
  && apt-get update \
  && apt-get install --no-install-recommends -y libnet-ssleay-perl \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/* \
  && cd /opt \
  && git clone https://github.com/sullo/nikto \
  && cd nikto \
  && git reset --hard ${NIKTO_VERSION} \
  && rm -rf .git \
  && update-alternatives --install /usr/bin/nikto.pl nikto.pl /opt/nikto/program/nikto.pl 9999 \
  && update-alternatives --install /usr/bin/replay.pl replay.pl /opt/nikto/program/replay.pl 9999

# DAST: Nmap
RUN set -x \
  && apt-get update \
  && apt-get install --no-install-recommends -y checkinstall libssl-dev flex bison \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/* \
  && cd /tmp \
  && curl -sL https://nmap.org/dist/nmap-${NMAP_VERSION}.tar.bz2 | tar -xjvf - \
  && cd nmap-${NMAP_VERSION} \
  && bash configure --without-zenmap --without-ndiff \
  && make \
  && env LINGUAS="" checkinstall -y \
  && cd .. \
  && rm -rf nmap-${NMAP_VERSION}

# DAST: Sslyze
RUN set -x \
  && pip3 install sslyze==${SSLYZE_VERSION} \
  && sslyze --update_trust_stores

# DAST: W3af
RUN set -x \
  && apt-get update \
  && apt-get install --no-install-recommends -y libxml2-dev libxslt1-dev zlib1g-dev \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/* \
  && pip install git+https://github.com/gitpython-developers/gitdb.git@857196a7312209eed5c84fca857ab6c486bcbd6b \
  && cd /opt \
  && git clone https://github.com/andresriancho/w3af.git \
  && cd w3af \
  && git reset --hard ${W3AF_VERSION} \
  && ./w3af_console; true \
  && sed 's/sudo //g' -i /tmp/w3af_dependency_install.sh \
  && sed 's/apt-get/apt-get -y/g' -i /tmp/w3af_dependency_install.sh \
  && sed 's|pip install|pip install --upgrade|g' -i /tmp/w3af_dependency_install.sh \
  && /tmp/w3af_dependency_install.sh \
  && rm -f /tmp/w3af_dependency_install.sh \
  && sed 's/dependency_check()/#dependency_check()/g' -i w3af_console \
  && rm -rf .git \
  && update-alternatives --install /usr/bin/w3af_console w3af_console /opt/w3af/w3af_console 9999

# DAST: ZAP
RUN set -x \
  && cd /opt \
  && curl -sL https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz | tar -xzvf - \
  && mv ZAP_${ZAP_VERSION} zap \
  && chmod +x /opt/zap/zap.sh \
  && update-alternatives --install /opt/zap/zap.jar zap.jar /opt/zap/zap-${ZAP_VERSION}.jar 9999
  # && /usr/bin/java -jar /opt/zap/zap.jar -cmd -addonupdate
  # && /usr/bin/java -jar /opt/zap/zap.jar -cmd -addoninstallall

# Legacy module depencies (will be removed as soon as all external modules adapted)
RUN set -x \
  && pip3 install lxml==4.2.5

# Dusty depencies
RUN set -x \
  && apt-get update \
  && apt-get install --no-install-recommends -y \
    libpq-dev \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*
