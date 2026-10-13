# Synthetic V3 differential fixture: latest tag + root user.
FROM nginx:latest
USER root
COPY . /app
EXPOSE 8080
CMD ["nginx", "-g", "daemon off;"]
