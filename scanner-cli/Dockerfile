FROM python:3.11-slim

WORKDIR /scan

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY scanner.py .
COPY rules/ ./rules/

# scanner.py takes the repo path to scan as an optional positional arg,
# defaulting to the current directory — the CI workflow mounts the checked-
# out repo and passes its path explicitly (see ecdat-scan.yml).
ENTRYPOINT ["python", "scanner.py"]
CMD ["/repo"]
