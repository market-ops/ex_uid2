defmodule ExUid2.Encryption.MasterPayload do
  @moduledoc false
  alias ExUid2.Keyring.Key
  alias ExUid2.Encryption.EncryptedToken

  @nonce_size 12
  @tag_size 16

  @type t :: %__MODULE__{
          version: 2 | 3,
          expires_ms: non_neg_integer(),
          site_key_id: non_neg_integer(),
          identity_iv: nil | <<_::128>>,
          identity_payload: binary()
        }

  defstruct [
    :version,
    :expires_ms,
    :site_key_id,
    :identity_iv,
    :identity_payload
  ]

  @spec decrypt(EncryptedToken.t(), Key.t()) :: {:ok, t()} | {:error, any()}
  def decrypt(%EncryptedToken{version: 2} = token, key) do
    :crypto.crypto_one_time(
      :aes_256_cbc,
      key.secret,
      token.master_iv,
      token.master_payload,
      false
    )
    |> parse_v2()
  end

  def decrypt(%EncryptedToken{version: version} = token, key) when version in [3, 4] do
    payload = token.master_payload
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

  @spec parse_v2(binary()) ::
          {:error, :invalid_master_payload} | {:ok, t()}
  def parse_v2(
        <<expires_ms::big-integer-64, site_key_id::big-integer-32,
          identity_iv::big-binary-size(16), identity_payload::binary>>
      ) do
    {
      :ok,
      %__MODULE__{
        version: 2,
        expires_ms: expires_ms,
        site_key_id: site_key_id,
        identity_iv: identity_iv,
        identity_payload: identity_payload
      }
    }
  end

  def parse_v2(_), do: {:error, :invalid_master_payload}

  def parse_v3(
        <<expires_ms::big-integer-64, _generated_ms::big-integer-64,
          _operator_site_id::big-integer-32, _operator_type::integer-8,
          _operator_version::big-integer-32, _operator_key_id::big-integer-32,
          site_key_id::big-integer-32, identity_payload::binary>>
      ) do
    {:ok,
     %__MODULE__{
       version: 3,
       expires_ms: expires_ms,
       site_key_id: site_key_id,
       identity_payload: identity_payload
     }}
  end

  def parse_v3(_), do: {:error, :invalid_master_payload}

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

    :crypto.crypto_one_time(:aes_256_cbc, key.secret, iv, payload, [
      {:padding, :pkcs_padding},
      {:encrypt, true}
    ])
  end

  @spec make_envelope(t()) :: binary()
  defp make_envelope(%__MODULE__{
         version: 2,
         expires_ms: expires_ms,
         site_key_id: site_key_id,
         identity_iv: identity_iv,
         identity_payload: identity_payload
       }) do
    <<expires_ms::big-integer-64, site_key_id::big-integer-32, identity_iv::big-binary-size(16),
      identity_payload::binary>>
  end

  defp make_envelope(%__MODULE__{
         version: version,
         expires_ms: expires_ms,
         site_key_id: site_key_id,
         identity_payload: identity_payload
       })
       when version in [3, 4] do
    <<expires_ms::big-integer-64, 0::168, site_key_id::big-integer-32, identity_payload::binary>>
  end
end
