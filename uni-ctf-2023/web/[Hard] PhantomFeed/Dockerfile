FROM --platform=amd64 python:3.12-alpine

# Install packages
RUN apk update && apk add --no-cache --update supervisor openssl nginx nodejs npm chromium chromium-chromedriver build-base freetype-dev && rm -rf /var/cache/apk/*

# Add chromium to PATH
ENV PATH="/usr/lib/chromium:${PATH}"

# Upgrade pip
RUN python -m pip install --upgrade pip
RUN python -m pip install --upgrade setuptools

# Copy flag
COPY flag.txt /flag.txt

# Setup app
RUN mkdir -p /app

# Switch working environment
WORKDIR /app

# Add application
COPY challenge .

# Switch working environment
WORKDIR /app/phantom-feed

# Install dependencies
RUN pip install -r requirements.txt

# Switch working environment
WORKDIR /app/phantom-market-backend

# Install dependencies
RUN pip install -r requirements.txt

# Switch working environment
WORKDIR /app/phantom-market-frontend

# Install dependencies
RUN npm install

# Build front-end
RUN npm run build

# Switch working environment
WORKDIR /app

# Setup supervisor
COPY conf/supervisord.conf /etc/supervisord.conf

# Setup nginx
RUN rm -rf /etc/nginx/conf.d/*
COPY conf/nginx.conf /etc/nginx/nginx.conf

# Expose port the server is reachable on
EXPOSE 1337

# Disable pycache
ENV PYTHONDONTWRITEBYTECODE=1

# Create database and start supervisord
COPY --chown=root entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]