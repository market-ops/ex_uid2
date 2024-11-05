# ExUid2

A library to interact with [Unified ID2](https://unifiedid.com/docs/intro)

It currently only handles the DSP part of UID2 (decrypting UID2 tokens in bid requests).

## Installation
Add `:ex_uid2` to the list of dependencies in mix.exs

```elixir
def deps do
  [
      {:ex_uid2, "~> 0.2.3"}
  ]
end
```

## Usage
Add the ExUid2 configuration to your application's config file:

```elixir
import Config

config :ex_uid2,
  base_url: "https://uid2_operator_server.com",
  api_key: "your_api_key",
  secret_key: "your_secret_key"

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
   identity_type: :email,
   version: 3,
   expires: ~U[2024-07-06 19:12:10.313Z]
 }}
```

If the keyring hasn't been properly fetched by the time a token decryption is attempted, an error tuple will be returned instead:

```elixir
ExUid2.Dsp.decrypt_token(<redacted>)
{:error, :no_keyring_stored}
```

## Mix Task
Tokens can be decrypted from the shell via the `decrypt` mix task:

```elixir
mix decrypt <redacted>

{:ok, %ExUid2.Uid2{uid: <redacted>, established_ms: 1721997317496, site_id: 262, site_key: %ExUid2.Keyring.Key{activates_ms: 1717193463, created_ms: 1717107063, expires_ms: 1725833463, id: 2316, secret: <redacted>, keyset_id: nil}, identity_scope: "UID2", version: 4, expires_ms: 1722256517496, identity_type: :phone}}
```

## Token decryption specification
Since no specification for the token decryption protocol could be found, the decryption
protocol has been guessed by reverse engineering the existing SDKs. It may include errors
and misconceptions, so this specification is likely to be erroneous or incomplete. However, it has been
shown to work for decoding encrypted UID2 tokens in a production environment.

### General flow
1. A keyring is periocically updated by querying the `/v2/key/bidstream` endpoint.
2. The encrypted token envelope is fetched from the bid request.
3. The token is base64 decoded.
4. The envelope is parsed to extract the token version and other info necessary for decryption.
5. The master key ID parsed from the envelope is used to get the master key from the keyring.
6. The master payload is decrypted.
7. The decrypted master payload is parsed to extract the expiration timestamp and other info necessary to decrypt the identity
8. The expiration timestamp is checked to ensure the token is still valid.
9. The site key ID parsed from the master payload is used to get the site key from the keyring.
10. The indentity payload is decrypted.

### `/v2/key/bidstream` request
While the `/v2/key/bidstream` endpoint is undocumented, The workflow to query UID2's endpoints is documented, the 
[Encrypting Requests and Decrypting Responses](https://unifiedid.com/docs/getting-started/gs-encryption-decryption#encryption-and-decryption-code-examples) documentation seem to apply there. It is what 
this library is doing.

### V2 tokens
1. The token is base64 decoded using the standard mode to get the envelope.
2. The envelope is parsed to extract the token version, the master key ID, the master IV and the master payload
3. The master key ID parsed from the envelope is used to get the master key from the keyring.
4. The master payload is decrypted using AES-256-CBC, the master key and the master IV.
5. The decrypted master payload is parsed to extract the expiration timestamp, the site key ID, the site IV and the identity payload.
6. The expiration timestamp is checked to ensure the token is still valid.
7. The site key ID parsed from the master payload is used to get the site key from the keyring.
8. The indentity payload is decrypted using AES-256-CBC, the site key and the site IV.
9. The decrypted identity payload is parsed to extract the site ID, the user ID length, the user ID binary and the established timestamp.

#### V2 Encrypted token envelope
| Offset (bytes) | Size (bytes) | Description |
| -------------- | ------------ | ----------- |
| 0              | 1            | UID2 token version |
| 1              | 4            | Master key ID. Must be uint32 big endian. |
| 5              | 16           | Master 128-bit initialization vector (IV), which is used to randomize data encryption. |
| 21             | N            | Master Payload (encrypted) |

#### V2 Decrypted Master Payload
| Offset (bytes) | Size (bytes) | Description |
| -------------- | ------------ | ----------- |
| 0              | 8            | Expiration time in milliseconds (Unix timestamp). Must be uint64 big endian. |
| 8              | 4            | Site key ID. Must be uint32 big endian. |
| 12             | 16           | Identity 128-bit initialization vector (IV), which is used to randomize data encryption. |
| 28             | N            | Identity Payload (encrypted) |

#### V2 Decrypted Identity Payload
| Offset (bytes) | Size (bytes) | Description |
| -------------- | ------------ | ----------- |
| 0              | 4            | Site ID. Must be uint32 big endian. |
| 4              | 4            | Length in bytes of ID binary. Must be uint32 big endian. |
| 8              | N            | Base64-encoded ID binary (the actual user ID). |
| 8 + N          | 4            | Unknown. |
| 12 + N         | 8            | Time when the identity was established in milliseconds (Unix timestamp). Must be uint64 big endian. |
| 20 + N         | M            | Unknown. |

### V3 Tokens
1. The token is base64 decoded using the standard mode to get the envelope.
2. The envelope is parsed to extract the token version, the identity type, master key ID and the master payload.
3. The master key ID parsed from the envelope is used to get the master key from the keyring.
4. The master payload is parsed and its data decrypted using AES-256-GCM and the master key.
5. The decrypted master payload is parsed to extract the expiration timestamp, the site key ID, and the identity payload.
6. The expiration timestamp is checked to ensure the token is still valid.
7. The site key ID parsed from the master payload is used to get the site key from the keyring.
8. The indentity payload is parsed and its data decrypted using AES-256-GCM and the site key.
9. The decrypted identity payload is parsed to extract the site ID, the user ID binary and the established timestamp.

#### V3 Encrypted token envelope
| Offset (bytes) | Size (bytes) | Description |
| -------------- | ------------ | ----------- |
| 0              | 1            | Identity type byte. |
| 1              | 1            | Version byte.  |
| 2              | 4            | Master Key ID. Must be uint32 big endian. |
| 6              | N            | Master Payload (encrypted) |

#### V3 Decrypted Master Payload
| Offset (bytes) | Size (bytes) | Description |
| -------------- | ------------ | ----------- |
| 0              | 8            | Expiration time in milliseconds (Unix timestamp). Must be uint64 big endian. |
| 8              | 8            | Timestamp when the token was generated in milliseconds (Unix timestamp). Must be uint64 big endian. |
| 16             | 4            | Operator Site ID (unused) |
| 20             | 1            | Operator Type (unused) |
| 21             | 4            | Operator Version (unused) |
| 25             | 4            | Operator Key ID (unused) |
| 29             | 4            | Site key ID. Must be uint32 big endian. |
| 33             | N            | Identity Payload (encrypted) |

#### V3 Decrypted Identity Payload
| Offset (bytes) | Size (bytes) | Description |
| -------------- | ------------ | ----------- |
| 0              | 4            | Site ID. Must be uint32 big endian. |
| 4              | 8            | Publisher ID. Must be uint64 big endian. |
| 12             | 4            | Client Key ID (unused) |
| 16             | 4            | Privacy Bits (unused) |
| 20             | 8            | Time when the identity was established in milliseconds (Unix timestamp). Must be uint64 big endian. |
| 28             | 8            | Unknown. |
| 36             | N            | Base64-encoded ID binary (the actual user ID). |

### V4 tokens
V4 tokens are exactly like V3 tokens, but are base64 encoded using the `urlsafe` mode.

## Benchmarks
Benchmarks can be run with the `:bench` env:

```
MIX_ENV=bench mix run benchmarks/keyring.exs --no-start
```