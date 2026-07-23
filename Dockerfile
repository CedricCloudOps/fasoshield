FROM python:3.12-slim AS base

# yara-python builds against libyara; keep the runtime image small by
# compiling in a dedicated stage.
FROM base AS build
RUN apt-get update && apt-get install -y --no-install-recommends gcc libmagic1 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir .

FROM base
RUN apt-get update && apt-get install -y --no-install-recommends libmagic1 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 fasoshield
COPY --from=build /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=build /usr/local/bin/fasoshield /usr/local/bin/fasoshield
COPY signatures /etc/fasoshield/signatures

ENV FASOSHIELD_SIGNATURES_DIR=/etc/fasoshield/signatures \
    FASOSHIELD_DATA_DIR=/var/lib/fasoshield
RUN mkdir -p /var/lib/fasoshield && chown fasoshield /var/lib/fasoshield
USER fasoshield
EXPOSE 8000
CMD ["uvicorn", "fasoshield.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
