# ExUid2

A library to interact with [Unified ID2](https://unifiedid.com/docs/intro)

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed
by adding `ex_uid2` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:ex_uid2, "~> 0.1.0"}
  ]
end
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
| 1              | 4            | Master key ID. Must be int32 big endian. |
| 5              | 16           | Master 128-bit initialization vector (IV), which is used to randomize data encryption. |
| 21             | N            | Master Payload (encrypted) |

### Decrypted Master Payload
| Offset (bytes) | Size (bytes) | Description |
| -------------- | ------------ | ----------- |
| 0              | 8            | Expiration time in milliseconds (Unix timestamp). Must be int64 big endian. |
| 8              | 4            | Site key ID. Must be int32 big endian. |
| 12             | 16           | Identity 128-bit initialization vector (IV), which is used to randomize data encryption. |
| 28             | N            | Identity Payload (encrypted)

### Decrypted Identity
| Offset (bytes) | Size (bytes) | Description |
| -------------- | ------------ | ----------- |
| 0              | 4            | Site ID. Must be int32 big endian. |
| 4              | 4            | Length in bytes of ID binary. Must be int32 big endian. |
| 8              | N            | Base64-encoded ID binary (the actual user ID). |
| 8 + N          | 4            | Unknown. |
| 12 + N         | 8            | Time when the identity was established in milliseconds (Unix timestamp). Must be int64 big endian. |
| 20 + N         | M            | Unknown. |

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at <https://hexdocs.pm/uid2_client_elixir>.

