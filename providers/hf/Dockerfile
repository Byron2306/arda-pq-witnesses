# Deploy the already built/reviewed witness image, not an implicit mutable base.
ARG WITNESS_IMAGE
FROM ${WITNESS_IMAGE}
ARG WITNESS_IMAGE
RUN suffix="${WITNESS_IMAGE##*@sha256:}"; \
    test "$suffix" != "$WITNESS_IMAGE" && test "${#suffix}" -eq 64 && \
    case "$suffix" in *[!0-9a-f]*) exit 1;; esac
EXPOSE 7860
CMD ["python3", "tools/serve_hf.py"]
