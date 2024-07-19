defmodule ExUid2.Api.Response do
  def decrypt_and_parse(response_bin, secret_key) do
    with {:decoded_response, decoded_response} <- {:decoded_response, :base64.decode(response_bin)},
         {:parsed_iv_and_rest, {:ok, {iv, rest}}} <- {:parsed_iv_and_rest, parse_iv_and_rest(decoded_response)},
         {:parsed_payload_and_tag, {:ok, {payload, tag}}} <- {:parsed_payload_and_tag, parse_payload_and_tag(rest)},
         {:decrypted_response, {:ok, response}} <- {:decrypted_response, decrypt(payload, iv, tag, secret_key)},
         {:response_map, {:ok, response_map}} <- {:response_map, Jason.decode(response, objects: :maps)} do
           {:ok, response_map}
    else
      {_, error} -> error
    end
  end

  defp decrypt(payload, iv, tag, secret_key) do
    case :crypto.crypto_one_time_aead(:aes_256_gcm, secret_key, iv, payload, <<>>, tag, false) do
      <<_ts_bin::binary-size(8), _nonce::binary-size(8), payload::binary>> ->
        {:ok, payload}
      :error ->
        {:error, :cannot_decrypt_payload}
      other ->
        {:error, {:unexpected_payload, other}}
    end
  end

  defp parse_iv_and_rest(<<iv::binary-size(12), rest::binary>>), do: {:ok, {iv, rest}}

  defp parse_iv_and_rest(_), do: {:error, :invalid_iv_and_rest}

  defp parse_payload_and_tag(rest_bin) do
    payload_size = byte_size(rest_bin) - 16
    case rest_bin do
      <<payload::binary-size(payload_size), tag::binary-size(16)>> ->
        {:ok, {payload, tag}}
      _ -> {:error, :invalid_payload_and_tag_binary}
    end
  end
end
