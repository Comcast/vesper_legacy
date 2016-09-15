FROM ubuntu:14.04

Maintainer Harsha Bellur

# MUST build Dockerfile as root

RUN apt-get update
RUN apt-get -y install curl
RUN apt-get -y install git

# Install Stable Go
WORKDIR /opt
RUN curl -O https://storage.googleapis.com/golang/go1.7.1.linux-amd64.tar.gz && tar -C /usr/local -xzf /opt/go1.7.1.linux-amd64.tar.gz
ENV PATH /usr/local/go/bin:/usr/local/bin:$PATH
ENV GOPATH /usr/local/vesper
ENV GOBIN $GOPATH/bin

# SSH key for github account
# The expectation is that the directory which has the "Dockerfile" must also contain 
# a directory named "keys" which contains the SSH key file for the github account 
COPY keys/id_rsa ~/.ssh/id_rsa
RUN chmod 700 ~/.ssh/id_rsa && echo "Host github.com\n\tStrictHostKeyChecking no\n" >> /root/.ssh/config

# Download and Install Vesper
WORKDIR /usr/local
RUN git clone git@github.com:Comcast/vesper.git
RUN go install app_server
