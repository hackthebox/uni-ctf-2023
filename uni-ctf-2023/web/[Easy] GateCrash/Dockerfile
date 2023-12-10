# Use a base image suitable for your needs, e.g., Ubuntu
FROM ubuntu:20.04

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    supervisor \
    make \
    musl-dev \ 
    gcc \
    curl \
    wget \
    git

# Download and install Choosenim
RUN curl https://nim-lang.org/choosenim/init.sh -sSf | sh -s -- -y

# Add Nim's bin directory to the PATH
ENV PATH="/root/.nimble/bin:${PATH}"

# Install nim
RUN choosenim update 1.2.4

# Set environment variables
ENV GO_VERSION 1.20
ENV GOPATH /go
ENV PATH $GOPATH/bin:/usr/local/go/bin:$PATH

# Download and install Go
RUN wget https://dl.google.com/go/go${GO_VERSION}.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz && \
    rm go${GO_VERSION}.linux-amd64.tar.gz

# Create a directory for your Go workspace
RUN mkdir -p $GOPATH/src $GOPATH/bin

# Copy flag
COPY flag.txt /flag.txt

# Setup app
RUN mkdir -p /app

# Switch working environment
WORKDIR /app

# Add application
COPY challenge .

# Setup supervisor
COPY config/supervisord.conf /etc/supervisord.conf

# Go to user api
WORKDIR /app/user_api

# Build server executable
RUN go build -o userApi main.go

# Go to control api
WORKDIR /app/control_api

# Build control api
RUN nimble install -y
RUN nimble build
RUN mv main controlApi

# Expose the port
EXPOSE 1337

# Supervisor
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]