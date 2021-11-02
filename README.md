# Dumb JOSE

Insecure library for a set of insecure formats.
It aims to provide inflexible verification for cases where you unfortunately can't avoid touching JWT.

## Requirements

* Go *>= 1.17*

## Disclaimer

Don't use JWT. You don't need me to tell you about it.
Likewise, you shouldn't need me to tell you that you shouldn't use this library.

## Goals

* Just enough JWT for people to speak commonly encountered OAuth 2.0 and alike.
* Don't allow for any of the sharp edges.
* Allow for binding domain parameters as much as possible to the public keys.

## Non-Goals

* Signing capabilities.
* Anything that has to do with encryption or key exchange.
* Be 100% compliant with the standard.

## License

This repository is licensed under the `BSD-3-Clause`. Refer to [LICENSE](https://github.com/aydinmercan/dumb-jose/blob/main/LICENSE) for more information.
