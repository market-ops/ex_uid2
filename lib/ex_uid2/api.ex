defmodule ExUid2.Api do
  @moduledoc false

  alias ExUid2.Api.Request
  alias ExUid2.Api.Response

  @spec post_encrypted_request(binary(), binary(), non_neg_integer()) :: {:ok, map()} | {:error, any()}
  def post_encrypted_request(path, payload, ts \\ :os.system_time(:millisecond)) do
    secret_key = get_secret_key()

    with {:request_body, {:ok, request_body}} <- {:request_body, Request.build_and_encrypt(payload, secret_key, ts)},
         {:response, {:ok, %Req.Response{status: 200, body: response_body}}} <- {:response, post(request_body, path)},
         {:parsed_response, {:ok, parsed_response}} <- {:parsed_response, Response.decrypt_and_parse(response_body, secret_key)} do
      {:ok, parsed_response}
    else
      {:response, {:ok, %Req.Response{status: _} = response}} -> {:error, response}
      {_, error} -> error
    end
  end

  defp post(payload, path) do
    base_url = Application.fetch_env!(:ex_uid2, :base_url)
    api_key = Application.fetch_env!(:ex_uid2, :api_key)
    req_options = Application.get_env(:ex_uid2, :req_opts, [])
    auth = {:auth, {:bearer, api_key}}
    body = {:body, payload}

    Req.post(base_url <> path, [body, auth | req_options])
  end

  defp get_secret_key() do
    Application.fetch_env!(:ex_uid2, :secret_key) |> :base64.decode()
  end
end
