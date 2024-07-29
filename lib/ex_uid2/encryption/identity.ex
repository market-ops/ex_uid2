defmodule ExUid2.Encryption.Identity do
  @moduledoc false
  alias ExUid2.Keyring.Key
  alias ExUid2.Encryption.MasterPayload

  @nonce_size 12
  @tag_size 16

  @type t :: %__MODULE__{
          version: 2 | 3,
          site_id: non_neg_integer(),
          id_len: non_neg_integer() | nil,
          id_bin: binary(),
          established_ms: non_neg_integer()
        }

  defstruct [
    :version,
    :site_id,
    :id_len,
    :id_bin,
    :established_ms
  ]

  @spec decrypt(MasterPayload.t(), Key.t()) :: {:ok, t()} | {:error, any()}
  def decrypt(%MasterPayload{version: 2} = master_payload, key) do
    %MasterPayload{site_iv: site_iv, site_payload: site_payload} = master_payload

    :crypto.crypto_one_time(:aes_256_cbc, key.secret, site_iv, site_payload, false)
    |> parse_v2()
  end

  def decrypt(%MasterPayload{version: 3} = master_payload, key) do
    payload = master_payload.site_payload
    payload_size = byte_size(payload)
    encrypted_data_size = payload_size - (@nonce_size + @tag_size)

    <<nonce::binary-size(@nonce_size), data::binary-size(encrypted_data_size),
      tag::binary-size(@tag_size)>> = payload

    case :crypto.crypto_one_time_aead(:aes_256_gcm, key.secret, nonce, data, <<>>, tag, false) do
      :error ->
        {:error, :cannot_decrypt_payload}

      decrypted_bin ->
        parse_v3(decrypted_bin)
    end
  end

  @spec parse_v2(binary()) :: {:ok, t()} | {:error, :invalid_v2_site_payload}
  def parse_v2(
        <<site_id::big-integer-32, id_len::big-integer-32, id_bin::binary-size(id_len),
          _::binary-size(4), established_ms::big-integer-64, _::binary>>
      ) do
    {
      :ok,
      %__MODULE__{
        version: 2,
        site_id: site_id,
        id_len: id_len,
        id_bin: id_bin,
        established_ms: established_ms
      }
    }
  end

  def parse_v2(_), do: {:error, :invalid_v2_site_payload}

  @spec parse_v3(binary()) :: {:ok, t()} | {:error, :invalid_v3_site_payload}
  def parse_v3(
        <<site_id::big-integer-32, _publisher_id::big-integer-64, _client_key_id::big-integer-32,
          _privacy_bits::binary-4, established_ms::big-integer-64, _unknown::binary-8,
          id_bin::binary>>
      ) do
    {:ok,
     %__MODULE__{
       version: 3,
       site_id: site_id,
       id_bin: id_bin,
       established_ms: established_ms
     }}
  end

  def parse_v3(_), do: {:error, :invalid_v3_site_payload}

  @spec make_envelope(t()) :: binary()
  defp make_envelope(%__MODULE__{
         version: 2,
         site_id: site_id,
         id_len: id_len,
         id_bin: id_bin,
         established_ms: established_ms
       }) do
    <<site_id::big-integer-32, id_len::big-integer-32, id_bin::binary, 0::big-integer-32,
      established_ms::big-integer-64>>
  end

  defp make_envelope(%__MODULE__{
         version: version,
         site_id: site_id,
         id_bin: id_bin,
         established_ms: established_ms
       })
       when version in [3, 4] do
    <<site_id::big-integer-32, 0::128, established_ms::big-integer-64, 0::64, id_bin::binary>>
  end

  @spec encrypt(t(), Key.t(), <<_::128>> | nil) :: binary()
  def encrypt(identity, key, iv \\ nil)

  def encrypt(%__MODULE__{version: version} = identity, key, nil) when version in [3, 4] do
    nonce = :crypto.strong_rand_bytes(@nonce_size)
    data = make_envelope(identity)

    {encrypted_data, tag} =
      :crypto.crypto_one_time_aead(:aes_256_gcm, key.secret, nonce, data, <<>>, true)

    <<nonce::binary, encrypted_data::binary, tag::binary>>
  end

  def encrypt(%__MODULE__{version: 2} = identity, key, iv) do
    payload = make_envelope(identity)

    :crypto.crypto_one_time(:aes_256_cbc, key.secret, iv, <<payload::binary>>, [
      {:padding, :pkcs_padding},
      {:encrypt, true}
    ])
  end
end
