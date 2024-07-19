defmodule ExUid2.Api.Request do
  @moduledoc false

  @doc """
  Builds an encrypted request body from a binary payloadp
  """
  def build_and_encrypt(payload, secret_key, ts) do
    with {:unencryted_envelope, {:ok, envelope}} <- {:unencryted_envelope, make_unencrypted_envelope(payload, ts)},
         {:encrypted_envelope, {:ok, encrypted_envelope}} <- {:encrypted_envelope, encrypt_envelope(envelope, secret_key)} do
           {:ok, encrypted_envelope}
    else
      {_, error} -> error
    end
  end

  def make_unencrypted_envelope(payload, ts, nonce \\ :crypto.strong_rand_bytes(8))
  def make_unencrypted_envelope(payload, ts, nonce)
      when is_binary(payload) and byte_size(nonce) == 8 and is_integer(ts) do
    ts_bin = :binary.encode_unsigned(ts, :big)
    pad = 8 - byte_size(ts_bin)
    encoded_ts = <<0::pad*8, ts_bin::binary>>
    {:ok, <<encoded_ts::binary, nonce::binary, payload::binary>>}
  end

  def make_unencrypted_envelope(_, _, _), do: {:error, :cannot_make_envelope}

  def encrypt_envelope(unencrypted_envelope, secret_key) when byte_size(secret_key) == 32 do
    iv = :crypto.strong_rand_bytes(12)

    encrypted_envelope =
      :crypto.crypto_one_time_aead(:aes_256_gcm, secret_key, iv, unencrypted_envelope, <<>>, true)
      |> make_encrypted_envelope(iv)
      |> :base64.encode()

    {:ok, encrypted_envelope}
  end

  def encrypt_envelope(_, _), do: {:error, :secret_key_must_be_32_bytes}

  defp make_encrypted_envelope({encrypted_payload, tag}, iv) do
    <<1, iv::binary, encrypted_payload::binary, tag::binary>>
  end
end
