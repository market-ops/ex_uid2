defmodule ResponseTest do
  use ExUnit.Case
  doctest ExUid2.Api.Response

  alias ExUid2.Api.Response

  test "Request and responses can be encrypted and parsed" do
    secret_key = :crypto.strong_rand_bytes(32)
    iv = :crypto.strong_rand_bytes(12)

    message = %{"message" => "test"}

    encoded_message = Jason.encode!(message)

    {:ok, {encrypted_message, tag}} = encrypt(encoded_message, iv, secret_key)

    {:ok, decrypted_message} = Response.decrypt(encrypted_message, iv, tag, secret_key)

    assert encoded_message == decrypted_message
  end

  test "Decryption and parsing return the right object" do
    secret_key = :crypto.strong_rand_bytes(32)
    iv = :crypto.strong_rand_bytes(12)

    message = %{"message" => "test"}

    json_message = Jason.encode!(message)

    encrypted_message = encrypt_and_wrap(json_message, iv, secret_key)

    {:ok, decoded_message} = Response.decrypt_and_parse(encrypted_message, secret_key)

    assert match?(decoded_message, message)
  end

  def encrypt(payload, iv, secret_key) do
    wrapped_payload = <<0::8*8, 0::8*8, payload::binary>>

    case :crypto.crypto_one_time_aead(:aes_256_gcm, secret_key, iv, wrapped_payload, <<>>, true) do
      {_encrypted_payload, _tag} = result ->
        {:ok, result}
      :error ->
        {:error, :encryption_error}
    end
  end

  def encrypt_and_wrap(payload, iv, secret_key) do
    {:ok, {encrypted_payload, tag}} = encrypt(payload, iv, secret_key)

    <<iv::binary, encrypted_payload::binary, tag::binary>>
    |> :base64.encode()
  end

end
