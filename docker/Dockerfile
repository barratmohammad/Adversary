# Adversary sandbox image: the verifier's tests run here with --network none, read-only rootfs.
# Build:  docker build -t adversary-sandbox:latest -f docker/Dockerfile docker/
# The image digest is recorded in every verdict (environment.sandbox.image_digest).
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=0 PIP_NO_CACHE_DIR=1
COPY requirements.lock /tmp/requirements.lock
RUN pip install --require-hashes -r /tmp/requirements.lock && rm /tmp/requirements.lock
RUN useradd -m -u 10001 verifier
USER verifier
WORKDIR /work
