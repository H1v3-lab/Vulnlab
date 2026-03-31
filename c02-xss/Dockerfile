FROM node:20-alpine

# Install Chromium for puppeteer admin-bot
RUN apk add --no-cache chromium

ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium-browser

WORKDIR /app

COPY package.json .
RUN npm install

COPY src/ ./src/

EXPOSE 3000
CMD ["node", "src/app.js"]
