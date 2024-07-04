defmodule ExUid2.Encryption.DecryptedMasterPayload do
  @type t :: %__MODULE__{expires_ms: non_neg_integer(), site_key_id: non_neg_integer(), identity_iv: <<_::128>>, identity_payload: binary()}

  defstruct [
    :expires_ms,
    :site_key_id,
    :identity_iv,
    :identity_payload
  ]
end
