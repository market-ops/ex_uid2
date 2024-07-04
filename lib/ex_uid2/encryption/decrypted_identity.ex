defmodule ExUid2.Encryption.DecryptedIdentity do
  @type t :: %__MODULE__{site_id: non_neg_integer(), id_len: non_neg_integer(), id_bin: binary(), established_ms: non_neg_integer()}

  defstruct [
    :site_id,
    :id_len,
    :id_bin,
    :established_ms
  ]

  @spec parse_identity(any()) ::
          {:error, :invalid_identity} | {:ok, ExUid2.Encryption.DecryptedIdentity.t()}
  def parse_identity(
    <<site_id::big-integer-32, id_len::big-integer-32, id_bin::binary-size(id_len),
      _::binary-size(4), established_ms::big-integer-64, _::binary>>
  ) do
  {
    :ok,
    %__MODULE__{
      site_id: site_id,
      id_len: id_len,
      id_bin: id_bin,
      established_ms: established_ms
    }
  }
  end

  def parse_identity(_) do
    {:error, :invalid_identity}
  end
end
