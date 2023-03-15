FROM getcarrier/dast:2.1-base
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

# Script to avoid OpenShift-Jenkins problems
COPY docker/scripts/nohung /usr/local/bin/nohung
RUN set -x && dos2unix /usr/local/bin/nohung && chmod 755 /usr/local/bin/nohung && chown 0:0 /usr/local/bin/nohung

# Dusty
COPY . /tmp/dusty
RUN set -x && pip3 install --no-cache-dir /tmp/dusty && rm -rf /tmp/dusty
ENV PYTHONUNBUFFERED 1
ENTRYPOINT ["dusty"]
