defmodule ExUid2.Encryption.EncryptedToken do
  @type t :: %__MODULE__{version: non_neg_integer(), master_key_id: non_neg_integer(), master_iv: <<_::128>>, master_payload: binary()}

  defstruct [
    :version,
    :master_key_id,
    :master_iv,
    :master_payload
  ]
end
