defmodule ExUid2.Encryption.MasterPayload do
  @moduledoc false
  alias ExUid2.Keyring.Key

  @type t :: %__MODULE__{
          expires_ms: non_neg_integer(),
          site_key_id: non_neg_integer(),
          identity_iv: <<_::128>>,
          identity_payload: binary()
        }

  defstruct [
    :expires_ms,
    :site_key_id,
    :identity_iv,
    :identity_payload
  ]

  @spec decrypt(binary(), Key.t(), <<_::128>>) :: {:ok, t()} | {:error, :invalid_master_payload}
  def decrypt(payload, key, iv) do
    :crypto.crypto_one_time(:aes_256_cbc, key.secret, iv, payload, false)
    |> parse()
  end

  @spec parse(binary()) ::
          {:error, :invalid_master_payload} | {:ok, t()}
  def parse(
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

  def parse(_), do: {:error, :invalid_master_payload}

  def encrypt(%__MODULE__{} = master_payload, key, iv) do
    payload_bin = make_envelope(master_payload)

    :crypto.crypto_one_time(:aes_256_cbc, key.secret, iv, payload_bin, [
      {:padding, :pkcs_padding},
      {:encrypt, true}
    ])
  end

  defp make_envelope(%__MODULE__{
         expires_ms: expires_ms,
         site_key_id: site_key_id,
         identity_iv: identity_iv,
         identity_payload: identity_payload
       }) do
    <<expires_ms::big-integer-64, site_key_id::big-integer-32, identity_iv::big-binary-size(16),
      identity_payload::binary>>
  end
end
