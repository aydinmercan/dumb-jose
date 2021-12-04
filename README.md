# Dumb JOSE

[![github-action](https://github.com/aydinmercan/dumb-jose/actions/workflows/test.yaml/badge.svg)](https://github.com/aydinmercan/dumb-jose/actions/workflows/test.yaml)

Insecure library for a set of insecure formats.
It aims to provide inflexible verification for cases where you unfortunately can't avoid touching JWT.

## Requirements

* Go *>= 1.17*

## Disclaimer

Don't use JWT. You don't need me to tell you about it.
Likewise, you shouldn't need me to tell you that you shouldn't use this library.

## Goals

* Just enough JWT for people to speak commonly encountered OAuth 2.0 (esp. with OIDC) and alike.
* Don't allow for any of the sharp edges.
* Allow for binding domain parameters as much as possible to the public keys.
* Extensive test coverage even if a particular case seems pedantic, guaranteed to be handled properly and/or improbable to be problematic.

## Non-Goals

* Signing capabilities.
* Anything that has to do with encryption, key exchange or MACs.
* Be 100% compliant with the standard.

## License

This repository is licensed under the `BSD-3-Clause`. Refer to [LICENSE](https://github.com/aydinmercan/dumb-jose/blob/main/LICENSE) for more information.
