FROM python:3.12-slim-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        iptables

WORKDIR /app
COPY pyproject.toml poetry.lock /app/
RUN pip install poetry==1.8.3 \
    && poetry config virtualenvs.create false \
    && poetry install

COPY http3_ip_spoofing.py /app/

ENTRYPOINT [ "python3", "/app/http3_ip_spoofing.py" ]
CMD [ "--help" ]
