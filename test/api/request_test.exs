defmodule Test.Api.RequestTest do
  use ExUnit.Case
  doctest ExUid2.Api.Request

  alias ExUid2.Api.Request

  test "Requests can be built and encrypted" do
    secret_key = :crypto.strong_rand_bytes(32)

    message = "Test"

    ts = :os.system_time(:millisecond)

    {:ok, encrypted_message} = Request.build_and_encrypt(message, secret_key, ts)
    {:ok, decryted_message} = decrypt_request(encrypted_message, secret_key)

    assert decryted_message == message
  end

  def decrypt_request(message, secret_key) do
    decoded_message = :base64.decode(message)
    <<1, iv::binary-size(12), rest::binary>> = decoded_message

    rest_size = byte_size(rest)
    payload_size = rest_size - 16

    <<encrypted_payload::binary-size(payload_size), tag::binary>> = rest

    case :crypto.crypto_one_time_aead(
           :aes_256_gcm,
           secret_key,
           iv,
           encrypted_payload,
           <<>>,
           tag,
           false
         ) do
      <<_ts::binary-size(8), _nonce::binary-size(8), payload::binary>> ->
        {:ok, payload}

      :error ->
        {:error, :decryption_error}

      other ->
        {:error, {:invalid_payload, other}}
    end
  end
end
