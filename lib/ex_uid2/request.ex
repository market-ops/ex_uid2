defmodule ExUid2.Request do
  def send(path, payload, ts \\ :os.system_time(:millisecond)) do
    base_url = Application.fetch_env!(:ex_uid2, :base_url)
    api_key = Application.fetch_env!(:ex_uid2, :api_key)
    secret_key = Application.fetch_env!(:ex_uid2, :secret_key) |> :base64.decode()

    with {:envelope, envelope} <- {:envelope, envelope(payload, ts)},
         {:encrypted_envelope, encrypted_envelope} <-
           {:encrypted_envelope, encrypted_envelope(envelope, secret_key)} do
      Req.post!(base_url <> path, auth: {:bearer, api_key}, body: encrypted_envelope)
    end
  end

  @doc """
  Wraps a binary payload into the standard unencrypted request data envelope
  specified here: https://unifiedid.com/docs/getting-started/gs-encryption-decryption#unencrypted-request-data-envelope

  ## Example

      iex> ExUid2.Request.envelope("payload", 1234, "abcdefgh")
      {:ok, "\\0\\0\\x04\\xD2abcdefghpayload"}

  """
  def envelope(payload, ts, nonce \\ :crypto.strong_rand_bytes(8))
      when byte_size(nonce) == 8 and is_integer(ts) do
    ts_bin = :binary.encode_unsigned(ts, :big)
    pad = 8 - byte_size(ts_bin)

    encoded_ts = <<0::pad*8, ts_bin::binary>>

    <<encoded_ts::binary, nonce::binary, payload::binary>>
  end

  def envelope(_, _, _), do: :error

  def encrypted_envelope(unencrypted_envelope, secret_key) do
    iv = :crypto.strong_rand_bytes(12)

    {encrypted_payload, tag} =
      :crypto.crypto_one_time_aead(:aes_256_gcm, secret_key, iv, unencrypted_envelope, <<>>, true)

    encrypted_envelope =
      <<1, iv::binary, encrypted_payload::binary, tag::binary>>
      |> :base64.encode()

    encrypted_envelope
  end

  def decrypt_response(<<iv::binary-size(12), rest::binary>>, secret_key) do
    rest_size = byte_size(rest)
    payload_size = rest_size - 16

    <<payload::binary-size(payload_size), tag::binary-size(16)>> = rest

    decrypted =
      :crypto.crypto_one_time_aead(:aes_256_gcm, secret_key, iv, payload, <<>>, tag, false)

    <<ts_bin::binary-size(8), nonce::binary-size(8), payload::binary>> = decrypted

    # IO.inspect(payload: Jason.decode(payload, objects: :maps))
    Jason.decode!(payload, objects: :maps)
  end
end
