To generate a self-signed cert for the example:

openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes \
  -keyout example/certs/dev-key.pem \
  -out example/certs/dev-cert.pem \
  -subj "/CN=localhost"
