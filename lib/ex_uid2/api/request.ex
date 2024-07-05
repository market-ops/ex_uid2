defmodule ExUid2.Api.Request do

  def post_encrypted_request(path, payload, ts \\ :os.system_time(:millisecond)) do
    secret_key = Application.fetch_env!(:ex_uid2, :secret_key) |> :base64.decode()

    with {:envelope, {:ok, envelope}} <- {:envelope, make_envelope(payload, ts)},
         {:encrypted_envelope, {:ok, encrypted_envelope}} <- {:encrypted_envelope, encrypt_envelope(envelope, secret_key)},
         {:response, %Req.Response{status: 200} = response} <- {:response, post(encrypted_envelope, path)},
         {:decrypted_response_body, decrypted_response_body} <- {:decrypted_response_body, decrypt_response(response.body, secret_key)} do
           decrypted_response_body
         else
          {:envelope, error} -> error
          {:encrypted_envelope, error} -> error
          {:response, response} -> {:error, response}
          {:decrypted_response_body, error} -> error
         end
  end

  def post(payload, path) do
    base_url = Application.fetch_env!(:ex_uid2, :base_url)
    api_key = Application.fetch_env!(:ex_uid2, :api_key)

    Req.post!(base_url <> path, auth: {:bearer, api_key}, body: payload)
  end

  @doc """
  Wraps a binary payload into the standard unencrypted request data envelope
  specified here: https://unifiedid.com/docs/getting-started/gs-encryption-decryption#unencrypted-request-data-envelope

  ## Example

      iex> ExUid2.Request.envelope("payload", 1234, "abcdefgh")
      {:ok, "\\0\\0\\x04\\xD2abcdefghpayload"}

  """
  def make_envelope(payload, ts, nonce \\ :crypto.strong_rand_bytes(8))
      when is_binary(payload) and byte_size(nonce) == 8 and is_integer(ts) do
    ts_bin = :binary.encode_unsigned(ts, :big)
    pad = 8 - byte_size(ts_bin)

    encoded_ts = <<0::pad*8, ts_bin::binary>>

    {:ok, <<encoded_ts::binary, nonce::binary, payload::binary>>}
  end

  def make_envelope(_, _, _), do: {:error, :cannot_make_envelope}

  def encrypt_envelope(unencrypted_envelope, secret_key) when byte_size(secret_key) == 32 do
    iv = :crypto.strong_rand_bytes(12)

    {encrypted_payload, tag} =
      :crypto.crypto_one_time_aead(:aes_256_gcm, secret_key, iv, unencrypted_envelope, <<>>, true)

    encrypted_envelope =
      <<1, iv::binary, encrypted_payload::binary, tag::binary>>
      |> :base64.encode()

    {:ok, encrypted_envelope}
  end

  def encrypt_envelope(_, _), do: {:error, :secret_key_must_be_32_bytes}

  def decrypt_response(<<iv::binary-size(12), rest::binary>>, secret_key) do

      IO.inspect(secret_key: secret_key)


      rest_size = byte_size(rest)
      payload_size = rest_size - 16

      <<payload::binary-size(payload_size), tag::binary-size(16)>> = rest

      decrypted =
        :crypto.crypto_one_time_aead(:aes_256_gcm, secret_key, iv, payload, <<>>, tag, false)

      IO.inspect(decrypted: decrypted)

      <<_ts_bin::binary-size(8), _nonce::binary-size(8), payload::binary>> = decrypted

      Jason.decode!(payload, objects: :maps)


    # try do

    #   rest_size = byte_size(rest)
    #   payload_size = rest_size - 16

    #   <<payload::binary-size(payload_size), tag::binary-size(16)>> = rest

    #   decrypted =
    #     :crypto.crypto_one_time_aead(:aes_256_gcm, secret_key, iv, payload, <<>>, tag, false)

    #   <<_ts_bin::binary-size(8), _nonce::binary-size(8), payload::binary>> = decrypted

    #   Jason.decode!(payload, objects: :maps)

    # rescue
    #   error -> error
    # end
  end
end
