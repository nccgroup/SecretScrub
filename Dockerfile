# Released as open source by NCC Group Plc - https://www.nccgroup.com/
#
# Developed by:
#     Andrew Kisliakov (andrew.kisliakov@nccgroup.com)
#
# Project link: https://www.github.com/nccgroup/secretscrub/
#
# Released under AGPL-3.0. See LICENSE for more information.

# Get Gitleaks container
FROM zricethezav/gitleaks:latest as gitleaks

FROM python:3 as cqccs
RUN git clone https://github.com/chris-anley/cq.git /app/cq && rm -rf /app/cq/.git
RUN git clone https://github.com/chris-anley/ccs.git /app/ccs && rm -rf /app/ccs/.git

FROM python:3

WORKDIR /app
COPY ./requirements.txt /app/
RUN pip install -r /app/requirements.txt

# Set up repositories for installation of third-party components
RUN apt-get update \
    && apt-get install -y wget apt-transport-https gnupg \
    && rm -rf /var/lib/apt/lists/*

# Install Trivy
RUN . /etc/os-release \
    && wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | apt-key add - \
    && echo deb https://aquasecurity.github.io/trivy-repo/deb $VERSION_CODENAME main | tee -a /etc/apt/sources.list.d/trivy.list \
    && apt-get update \
    && apt-get install trivy \
    && rm -rf /var/lib/apt/lists/*

# Install Gitleaks
COPY --from=gitleaks /usr/bin/gitleaks /usr/bin/

# Install cq and ccs
RUN mkdir /app/cq && mkdir /app/ccs
COPY --from=cqccs /app/. /app/

# Install main application and dependencies
COPY . /app/

# Set up new user
RUN useradd --uid 9999 --create-home secretscrub
USER secretscrub

ENTRYPOINT ["/bin/bash", "run-docker.sh"]