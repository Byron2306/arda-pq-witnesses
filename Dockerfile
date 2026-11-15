# Supply independently reviewed immutable images for BOTH arguments.
ARG NODE_IMAGE
ARG BASE_IMAGE
FROM ${NODE_IMAGE} AS node-runtime
FROM ${BASE_IMAGE}
ARG BASE_IMAGE
ARG NODE_IMAGE
RUN for image in "$BASE_IMAGE" "$NODE_IMAGE"; do \
      suffix="${image##*@sha256:}"; \
      test "$suffix" != "$image" && test "${#suffix}" -eq 64 || exit 1; \
      case "$suffix" in *[!0-9a-f]*) exit 1;; esac; \
    done
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-cryptography python3-yaml python3-nacl openssl gcc make libc6-dev libssl-dev libstdc++6 libatomic1 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=node-runtime /usr/local/bin/node /usr/local/bin/node
WORKDIR /app
COPY . /app
RUN python3 run_verification.py
USER 1000:1000
EXPOSE 7860
CMD ["python3", "tools/serve_hf.py"]
