FROM node:20-alpine

WORKDIR /app

COPY package.json ./
RUN npm install

COPY . .

RUN addgroup -g 1000 appgroup \
    && adduser -u 1000 -G appgroup -s /bin/sh -D appuser \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 5173

CMD ["npm", "run", "dev"]
