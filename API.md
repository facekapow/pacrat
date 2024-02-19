# Pacrat Server API

## `GET /auth_info`

TODO

## `GET /check_token`

TODO

## `POST /upload_package`

Upload a package to the server. This endpoint requires administrator access.
This will sign the package with the uploader's identity, add it to the database, and then
sign the database with the uploader's identity as well.

### Parameters

This endpoint requires authorization (via the `Authorization` header) with an access token
that has administrator privileges. The user associated with the access token will be associated
with the uploaded package and updated database via their signature from a PGP key specific to
the uploader (previously uploaded and stored on the server).

Of course, this endpoint requires the package to be uploaded as the body of the request. It should
be uploaded as a standard multipart file upload under the name `package`.

### Security

Signing is performed automatically on the server side, which means the server must trust the
uploader. This is done by trusting a third-party (the OpenID Connect identity provider) to
verify the uploader's identity and access level and issuing an access token which is then
provided by the client along with the request. This is enough to certify to the server that
the uploader is who they say they are and has the necessary access.
