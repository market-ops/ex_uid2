defmodule ExUid2.DecryptedToken do
  @type t :: %__MODULE__{}
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
