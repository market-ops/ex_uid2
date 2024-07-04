defmodule ExUid2.Encryption.DecryptedIdentity do
  @type t :: %__MODULE__{site_id: non_neg_integer(), id_len: non_neg_integer(), id_bin: binary(), established_ms: non_neg_integer()}

  defstruct [
    :site_id,
    :id_len,
    :id_bin,
    :established_ms
  ]
end
