FROM node:22-trixie-slim

# Install Coral via the official install script
RUN apt-get update && apt-get install -y curl ca-certificates && rm -rf /var/lib/apt/lists/*
ENV CORAL_INSTALL_DIR=/usr/local/bin
RUN curl -fsSL https://withcoral.com/install.sh | sh

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY . .

ENV PORT=3000
ENV CORAL_CONFIG_DIR=/coral-config
RUN mkdir -p /coral-config

EXPOSE 3000
CMD ["node", "server.js"]
