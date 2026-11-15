FROM node:24-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY circuits ./circuits
COPY src ./src
ENV PORT=8788
EXPOSE 8788
CMD ["node", "src/server.js"]
