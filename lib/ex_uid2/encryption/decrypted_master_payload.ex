defmodule ExUid2.Encryption.DecryptedMasterPayload do
  @type t :: %__MODULE__{expires_ms: non_neg_integer(), site_key_id: non_neg_integer(), identity_iv: <<_::128>>, identity_payload: binary()}

  defstruct [
    :expires_ms,
    :site_key_id,
    :identity_iv,
    :identity_payload
  ]

  @spec parse_master_payload(any()) ::
          {:error, :invalid_master_payload} | {:ok, ExUid2.Encryption.DecryptedMasterPayload.t()}
  def parse_master_payload(
    <<expires_ms::big-integer-64, site_key_id::big-integer-32,
      identity_iv::big-binary-size(16), identity_payload::binary>>
    ) do
    {
      :ok,
      %__MODULE__{
        expires_ms: expires_ms,
        site_key_id: site_key_id,
        identity_iv: identity_iv,
        identity_payload: identity_payload
      }
    }
  end

  def parse_master_payload(_), do: {:error, :invalid_master_payload}
end
