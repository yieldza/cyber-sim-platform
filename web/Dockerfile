FROM nginx:1.27-alpine

# Replace default config with the proxy config that fronts /api/ and
# /agent-c2/ onto the api service.
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Bake static assets into the image
COPY index.html /usr/share/nginx/html/
COPY styles.css /usr/share/nginx/html/
COPY app.js    /usr/share/nginx/html/

EXPOSE 80
