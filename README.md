# ExUid2

A library to interact with [Unified ID2](https://unifiedid.com/docs/intro)

It currently only handles the DSP part of UID2 (decrypting UID2 tokens in bid requests).

## Installation
TODO

## Usage
Add the ExUid2 configuration to your application's config file:

```elixir
import Config

config :ex_uid2,
  base_url: "https://uid2_operator_server.com",
  api_key: "your_api_key",
  secret_key: "your_secret_key"

```

Start the DSP server

```elixir
ExUid2.Dsp.start_link()
```

or add it to a supervisor (e.g. in your `application.ex` file)

```elixir
children = [
  ExUid2.Dsp
]

Supervisor.start_link(children, ...)
```

Once started, the application will periodically request a fresh keyring from the configured UID2 operator server. Encrypted tokens
can then be decrypted.

```elixir
ExUid2.Dsp.decrypt_token(<redacted>)
{:ok,
 %ExUid2.Uid2{
   uid: <redacted>,
   established: ~U[2024-07-02 01:17:56.501Z],
   site_id: 11,
   site_key: %ExUid2.Keyring.Key{
     activates: 1717269873,
     created: 1717183473,
     expires: 1725909873,
     id: 2383,
     secret: <redacted>,
     keyset_id: nil
   },
   identity_scope: "UID2",
   identity_type: nil,
   advertising_token_version: 2,
   expires: ~U[2024-07-06 19:12:10.313Z]
 }}
```

If the keyring hasn't been properly fetched by the time a token decryption is attempted, an error tuple will be returned instead:

```elixir
ExUid2.Dsp.decrypt_token(<redacted>)
{:error, :no_keyring_stored}
```

## Token decryption specification
Since no specification for the token decryption protocol could be found, the decryption
protocol has been found by reverse engineering the existing SDKs and may include errors
and misconceptions, so this specification may be erroneous or incomplete, but has been
shown to work for decoding encrypted UID2 tokens.

### General flow
1. A keyring is periocically updated by querying the `/v2/key/sharing` endpoint.
2. The encrypted token envelope is fetched from the bid request
3. The envelope is parsed to extract the token version, the master key ID, the master IV and the master payload
4. The right key to decrypt the master payload is obtained by looking up the master key ID in the keyring.
5. The master payload is decrypted using AES-256-CBC, the master key and the master IV.
6. The decrypted master payload is parsed to extract the expiration timestamp, the site key ID, the identity IV and the identity payload.
7. The expiration timestamp is checked to ensure the token is still valid.
8. The right key to decrypt the identity is obtained by looking up the site key ID in the keyring.
9. The indentity payload is decrypted using AES-256-CBC, the site key and the identity IV.
10. The decrypted identity payload is parsed to extract the site ID, the identity length, the identity binary and the established timestamp.

### `/v2/key/sharing` request
While the `/v2/key/sharing` endpoint is undocumented, The workflow to query UID2's endpoints is documented, the 
[Encrypting Requests and Decrypting Responses](https://unifiedid.com/docs/getting-started/gs-encryption-decryption#encryption-and-decryption-code-examples) documentation seem to apply there. It is what 
this library is doing.

### Encrypted token envelope
| Offset (bytes) | Size (bytes) | Description |
| -------------- | ------------ | ----------- |
| 0              | 1            | UID2 token version |
| 1              | 4            | Master key ID. Must be uint32 big endian. |
| 5              | 16           | Master 128-bit initialization vector (IV), which is used to randomize data encryption. |
| 21             | N            | Master Payload (encrypted) |

### Decrypted Master Payload
| Offset (bytes) | Size (bytes) | Description |
| -------------- | ------------ | ----------- |
| 0              | 8            | Expiration time in milliseconds (Unix timestamp). Must be uint64 big endian. |
| 8              | 4            | Site key ID. Must be uint32 big endian. |
| 12             | 16           | Identity 128-bit initialization vector (IV), which is used to randomize data encryption. |
| 28             | N            | Identity Payload (encrypted)

### Decrypted Identity
| Offset (bytes) | Size (bytes) | Description |
| -------------- | ------------ | ----------- |
| 0              | 4            | Site ID. Must be uint32 big endian. |
| 4              | 4            | Length in bytes of ID binary. Must be uint32 big endian. |
| 8              | N            | Base64-encoded ID binary (the actual user ID). |
| 8 + N          | 4            | Unknown. |
| 12 + N         | 8            | Time when the identity was established in milliseconds (Unix timestamp). Must be uint64 big endian. |
| 20 + N         | M            | Unknown. |

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at <https://hexdocs.pm/uid2_client_elixir>.

