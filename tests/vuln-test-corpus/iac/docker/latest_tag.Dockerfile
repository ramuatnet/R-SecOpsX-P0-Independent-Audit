FROM node:latest
USER app
WORKDIR /app
CMD ["node", "index.js"]
