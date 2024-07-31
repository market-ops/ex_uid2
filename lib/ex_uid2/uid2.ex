defmodule ExUid2.Uid2 do
  @moduledoc """
  Struct holding the decrypted and parsed UID2 token.
  """

  @typedoc """
  Struct holding the decrypted and parsed UID2 token.

  * `:uid` - User's unique ID. This should always be a 44 bytes base64-encoded hashed ID.

  * `:established_ms` - The time when the token was first created (Unix timestamp in milliseconds)

  * `:site_id` - The site's ID used for finding the right decryption key.

  * `site_key` - The key found in the Keyring for the given `site_id`

  * `identity_scope` - The identity scope found in the keyring (should probably always be "UID2").

  * `identity_type` - Whether this is an hashed email or phone number. Will be `:unknown` for V2 tokens.

  * `version` - The advertising token version.

  * `expires_ms` - The time after which the token will be expired (Unix timestamp in milliseconds).
  """

  @type t :: %__MODULE__{
          uid: binary(),
          established_ms: non_neg_integer(),
          site_id: non_neg_integer(),
          site_key: ExUid2.Keyring.Key.t(),
          identity_scope: binary(),
          identity_type: :phone | :email | :unknown,
          version: non_neg_integer(),
          expires_ms: non_neg_integer()
        }

  defstruct [
    :uid,
    :established_ms,
    :site_id,
    :site_key,
    :identity_scope,
    :version,
    :expires_ms,
    identity_type: :unknown
  ]

  def new(map) do
    %__MODULE__{
      uid: map[:uid],
      established_ms: map[:established_ms],
      site_id: map[:site_id],
      site_key: map[:site_key],
      identity_scope: map[:identity_scope],
      identity_type: map[:identity_type],
      version: map[:version],
      expires_ms: map[:expires_ms]
    }
  end
end
