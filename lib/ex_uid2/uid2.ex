defmodule ExUid2.Uid2 do
  @moduledoc """
  Struct holding the decrypted and parsed UID2 token

  Fields:

  * `:uid` - User's unique ID

  * `:established_ms` - The time when the token was first created (Unix timestamp in milliseconds)

  * `:site_id` - The site's ID used for finding the right decryption key

  * `site_key` - The key found in the Keyring for the given `site_id`

  * `identity_scope` - The identity scope found in the keyring (should probably always be "UID2")

  * `identity_type` - Unknown

  * `advertising_token_version` - The token version.

  * `expires_ms` - The time after which the token will be expired (Unix timestamp in milliseconds)
  """

  @type t :: %__MODULE__{
          uid: binary(),
          established_ms: non_neg_integer(),
          site_id: non_neg_integer(),
          site_key: ExUid2.Keyring.Key.t(),
          identity_scope: binary(),
          identity_type: any(),
          advertising_token_version: non_neg_integer(),
          expires_ms: non_neg_integer()
        }

  defstruct [
    :uid,
    :established_ms,
    :site_id,
    :site_key,
    :identity_scope,
    :identity_type,
    :advertising_token_version,
    :expires_ms
  ]
end
