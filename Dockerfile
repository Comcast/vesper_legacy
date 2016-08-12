FROM ubuntu:14.04

Maintainer Harsha Bellur

RUN apt-get update
RUN apt-get -y install curl
RUN apt-get -y install git

# Install Stable Go
WORKDIR /opt
RUN curl -O https://storage.googleapis.com/golang/go1.6.3.linux-amd64.tar.gz && tar -C /usr/local -xzf /opt/go1.6.3.linux-amd64.tar.gz
ENV PATH /usr/local/go/bin:/usr/local/bin:$PATH
ENV GOPATH /usr/local/vesper
ENV GOBIN $GOPATH/bin

# Download and Install Vesper
WORKDIR /usr/local
# SSH key for github account
# The expectation is that the SSH key file to github account is present in $HOME/.ssh directory
# with the right permissions
RUN git clone git@github.com:Comcast/vesper.git
RUN go install app_server
