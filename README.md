# srp-auth

#### A JavaScript implementation of the Secure Remote Password (SRP) protocol.

SRP is a protocol which allows a server to authenticate a client without transmitting the client's password in plain text. SRP is an implementation of password-authenticated key exchange (PAKE). SRP (as a protocol) is used by services such as ProtonMail and AWS Cognito.

## The principles
- Attackers have complete knowledge of the protocol.
- Attackers have access to a large dictionary of commonly used passwords.
- Attackers can eavesdrop on all communications between client and server
- Attackers can intercept, modify, and forge arbitrary messages between client and server.
- A mutually trusted third party is not available.

[[srp.stanford.edu]](http://srp.stanford.edu/whatisit.html)

In essence, SRP *should* make it possible to carry out authentication publicly, between a client and a server, without ever transmitting the client's password. Additionally, at no point does the server have access to the client's plain text password.

Keep in mind that this library **does not** verify whether or not a message sent between the client and server has been modified. This library purely implements a PAKE-like authentication protocol. If you need to do this, you must handle verification yourself.

## Use cases
Really, anywhere you are using usernames and password to authenticate users, you can use SRP!

**If the connection IS NOT secure:**   
SRP *should* prevent an attacker from determining the user's plain text password. The server *should* also not be able to derive the user's plain text password.

**If the connection IS secure:**   
If you are already using a technology such as HTTPS, it is unlikely that SRP will provide any tangible protection against MitM attacks, as HTTPS should do this for you. SRP *should* prevent the server from deriving the user's plain text password.

## Best practices

If the library throws an error, start the session over from the beginning. Throw everything that the client and server have already agreed upon away and have the client reinitialize.

An `SRPError` indicates that either you have passed invalid variables to the library, called functions out-of-order, or (rarely) the library has malfunctioned.

An `SRPSecurityViolation` indicates that something has gone severely wrong, and the library does not think that the other party is geniune. For example, if the client or server fails authentication. If this happens, even whilst the user is authenticated, deauthenticate them and require reauthentication.

# Example

## Setup

### Client-side

```ts
username: string
password: string
```

```ts
import { ClientSetup, Algorithm, Groups } from 'srp-auth';

const setup = new ClientSetup({
    username: username,
    password: password,
    group: Groups.b2048,
    algorithm: Algorithm.SHA3_512,
});

const { I, encoded } = await setup.init();

// send I, encoded.v and encoded.s to the server
```

### Server-side

```ts
I: string
v: string
s: string
```

```ts
import { ServerSetup, Algorithm, Groups } from 'srp-auth';

const setup = new ServerSetup({
    I: I,
    v: v,
    s: s,
    group: Groups.b2048,
    algorithm: Algorithm.SHA3_512,
});

await setup.verify();

// store I, v and s in the server's database.
// I is the username
```

## Authenticating

TODO

# API

## class ClientSetup(config: ClientSetupConfig)
- `config.username` (string) :: The username used for authentication.
- `config.password` (string) :: The plain text password. There is no need to hash this beforehand!
- `config.salt`? (Uint8Array) :: The salt to use. If undefined, one will be securely generated.
- `config.saltLength`? (number) :: The amount of bits to be used in the generated salt. Defaults to `192` bits. Ignored when `config.salt` is provided.
- `group`: (Group) :: The SRP group to use. The built-in groups are from [RFC 5054](https://datatracker.ietf.org/doc/html/rfc5054#appendix-A).
- `algorithm` (Algorithm) :: The hashing algorithm to use.

### await init(): Promise\<ClientSetupResult\>
Computes `v` and `s`, to be used by the server. You can send `encoded.v` and `encoded.s` to the server, along with `I`.

**Returns:** ClientSetupResult
- `I` (string) :: The username in plain text. This should be sent to the server, **not the original username provided to the library**!
- `raw.v` (Uint8Array) :: The verifier (`v`) as a Uint8Array.
- `raw.s` (Uint8Array) :: The salt generated by the client (`s`) as a Uint8Array.
- `encoded.v` (string) :: The verifier (`v`) encoded as hex.
- `encoded.s` (string) :: The salt generated by the client (`s`) encoded as hex.

## class ClientAuthenticate(config: ClientAuthenticateConfig)
- `config.username` (string) :: The username used for authentication.
- `config.password` (string) :: The plain text password. There is no need to hash this beforehand!
- `group` (Group) :: The SRP group to use. The built-in groups are from [RFC 5054](https://datatracker.ietf.org/doc/html/rfc5054#appendix-A).
- `algorithm` (Algorithm) :: The hashing algorithm to use.

### await init(): Promise\<ClientAuthenticateInit\>
Computes `A`, the client's ephemeral session key. This should be sent to the server, along with `I`.

**Returns:** ClientAuthenticateInit
- `I` (string) :: The username in plain text. This should be sent to the server, **not the original username provided to the library**!
- `raw.A` (Uint8Array) :: The client's ephemeral session key (`A`) as a Uint8Array.
- `encoded.A` (string) :: The client's ephemeral session key (`A`) encoded as hex.

### await exchange(B: string | Uint8Array, s: string | Uint8Array): Promise\<void\>
Computes `u` (a combination of both the client and server's ephemeral session keys `A` and `B`), `S` (the session key) and `K` (the client's key).

- `B` (string | Uint8Array) :: The server's ephemeral session key (`B`), which should be provided by the server. If a string is provided, it must be hex encoded.
- `s` (string | Uint8Array) :: The salt (`s`) which was originally calculated by the client but is now stored by the server. If a string is provided, it must be hex encoded.

**Returns:** *void*

### await authenticate(): Promise\<ClientAuthenticateResult\>
Computes `M1` which can be used by the server to verify the client's authenticity, without sending the user's password in plain text.

**Returns:** ClientAuthenticateResult
- `raw.M1` (Uint8Array) :: The client's authentication key (`M1`), derived from `N`, `g`, `s`, `A`, `B`, `I` and `K`, as a Uint8Array.
- `encoded.M1` (string) :: The client's authentication key (`M1`) encoded as hex.

### await verifyServer(M2: string | Uint8Array): Promise\<void\>
Verifies that the server holds the verifier (`v`) that was originally created by the client during setup. This authenticates the server.

- `M2` (string | Uint8Array) :: The server's authentication key (`M2`), which should be provided by the server. If a string is provided, it must be hex encoded.

> ⚠️ **Warning**: `verifyServer(...)` will throw an `SRPSecurityViolation` if `M2` does not match its expected value. If an error is thrown, the client may still have passed authentication, but the server **cannot** be trusted. The server is either misconfigured, or is a malicious attacker who is blindly accepting anything you throw at them. You may be caught in the middle of a MitM attack!

**Returns:** *void*

# Performance
Running on the main Node.JS thread. No multithreading.

## SetupClient

| Group       | Algorithm | Speed (OPS/s) |
|-------------|-----------|---------------|
| 1024 bits   | SHA3-256  | 225/s         |
| 1024 bits   | SHA3-512  | 158/s         |
| 2048 bits   | SHA3-256  | 114/s         |
| 2048 bits   | SHA3-512  | 66/s          |
| 4096 bits   | SHA3-256  | 41/s          |
| 4096 bits   | SHA3-512  | 22/s          |

<!--# Behind the scenes

`H(...)` = A hashing algorithm, such as SHA-256.   
`I` = The user's 'identity' (username)   
`p` = The plain text password   
`x` = A token calculated by the client   
`v` = The verifier   

✓ = Handled by this library.   
~ = Handled by the user of the library.   

## Setup

### 1. Client

✓ Generates a random salt (`s`).   
✓ Calculates `id = H(I + ':' + p)`.   
✓ Calculates `x = H(s + id)`.   
✓ Calculates `v = g ^ x % N`.   
~ Sends `I`, `s` and `v` to the server.   

> ⚠️ **`x` is private** and should never be stored or transmitted by the client. This includes to the server. Anyone with `x` can derive the plain text password.   

### 2. Server

~ Receives `I`, `s` and `v` from the client. `I` should be stored as the user's username, and `s` and `v` should be stored to verify the user's password in the future.   

## Authentication

### 1. Client

✓ Generates a random value (`a`).   
✓ Calculates `A = g ^ a`.   
~ Sends `I` and `A` to the server.-->   
