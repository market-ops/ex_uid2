defmodule ExUid2.DecryptedToken do
  defstruct [
    :uid,
    :established,
    :site_id,
    :site_key,
    :identity_scope,
    :identity_type,
    :advertising_token_version,
    :expires
  ]
end
