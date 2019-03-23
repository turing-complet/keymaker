Welcome to keymaker, the swiss army knife for cryptography. It's meant to provide an interface 
for common cryptographic operations in the form of a docker container that can be run as a
REST API for as a cli tool. Keymaker uses native go crypto libraries to provide reliable implementations
but use at your own risk.

Usage:

First build it - `docker build . t keymaker:latest` (I will publish it eventually).

Run - `docker run -p 8080:8080 keymaker:latest`

Then use either the REST API or the cli (not implemented yet).

REST API:

Hashing:
```
GET /sha256/{data}?encoding={bytes, hex}
GET /sha512/{data}?encoding={bytes, hex}
```

Symmetric encryption:
```
POST /symmetrickeys?bits=<int>
Response: { keyid (guid): key (bytes) }
e.g.
{
  "ID": "4b3b1067-4a57-48ce-a89a-a454d15a0fa8",
  "Key": "p6SdAbyQIO4eL36GUsig7hTaR42SoOEnfj7PT83L4SQ="
}

GET /listkeys
GET /aes/encrypt/{plaintext}?keyid=<keyid>
GET /aes/decrypt/{plaintext}?keyid=<keyid>

```

Other:
```
GET /
Response: documentation

GET /uuid
Response: a uuid, in case you needed a uuid
```