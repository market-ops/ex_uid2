defmodule ExUid2.Encryption.Identity do
  @moduledoc false
  alias ExUid2.Keyring.Key

  @type t :: %__MODULE__{
          site_id: non_neg_integer(),
          id_len: non_neg_integer(),
          id_bin: binary(),
          established_ms: non_neg_integer()
        }

  defstruct [
    :site_id,
    :id_len,
    :id_bin,
    :established_ms
  ]

  @spec decrypt(binary(), Key.t(), <<_::128>>) :: {:ok, t()} | {:error, :invalid_identity_payload}
  def decrypt(payload, key, iv) do
    :crypto.crypto_one_time(:aes_256_cbc, key.secret, iv, payload, false)
    |> parse()
  end

  @spec encrypt(t(), Key.t(), <<_::128>>) :: binary()
  def encrypt(%__MODULE__{} = identity, key, iv) do
    payload = make_envelope(identity)

    :crypto.crypto_one_time(:aes_256_cbc, key.secret, iv, <<payload::binary>>, [
      {:padding, :pkcs_padding},
      {:encrypt, true}
    ])
  end

  @spec parse(any()) :: {:ok, t()} | {:error, :invalid_identity_payload}
  def parse(
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

  def parse(_), do: {:error, :invalid_identity_payload}

  @spec make_envelope(t()) :: binary()
  def make_envelope(%__MODULE__{
        site_id: site_id,
        id_len: id_len,
        id_bin: id_bin,
        established_ms: established_ms
      }) do
    <<site_id::big-integer-32, id_len::big-integer-32, id_bin::binary, 0::big-integer-32,
      established_ms::big-integer-64>>
  end
end
