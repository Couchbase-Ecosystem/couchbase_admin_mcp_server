# Corporate CA certificates for the image build

Drop your organization's root and intermediate certificates here, as **`.crt`
files in PEM format**, and they are installed into the image's trust store
before `pip` runs.

## Why this directory exists

The build failed on this network with:

```
SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED]
certificate verify failed: self-signed certificate in certificate chain'))
Could not fetch URL https://pypi.org/simple/mcp/
ERROR: No matching distribution found for mcp<2.0,>=1.10
```

A proxy that re-signs outbound TLS presents a certificate chain rooted in an
authority the machine trusts and the container does not. `python:3.12-slim`
carries its own CA set, so pip inside the build sees an unknown issuer and
refuses — correctly.

The same class of problem affects `uv` (`UV_SYSTEM_CERTS=1`), `npm`
(`NODE_EXTRA_CA_CERTS`) and the running container (`REQUESTS_CA_BUNDLE`, set by
the compose files). This directory covers the one they don't: **build time**.

## What NOT to do

`pip install --trusted-host pypi.org` and `PIP_DISABLE_SSL_VERIFICATION` make
the error go away by turning the proxy into an unauthenticated man in the
middle, for every package the image installs. Adding the corporate root is the
fix; skipping verification is not.

## Exporting the certificates

Windows, from the store the machine already trusts:

```powershell
$out = "deploy\ca\corp-roots.crt"
Get-ChildItem Cert:\LocalMachine\Root, Cert:\LocalMachine\CA | ForEach-Object {
    "-----BEGIN CERTIFICATE-----"
    [Convert]::ToBase64String($_.RawData, 'InsertLineBreaks')
    "-----END CERTIFICATE-----"
} | Set-Content -Encoding ascii $out
```

Then `docker build` as normal. Nothing else changes.

## An empty directory is fine

On a network with no interception, leave this as it is. The build copies the
directory, finds no `.crt` files, and carries on — `update-ca-certificates` is a
no-op and pip uses the image's own trust store.

## Do not commit real certificates

`.gitignore` excludes `*.crt` here. The certificates are not secret, but they
are site-specific: committing one means every other site builds an image
trusting an authority that has nothing to do with them.
