defmodule ExUid2.Api do
  alias ExUid2.Api.Request
  alias ExUid2.Api.Response

  def post_encrypted_request(path, payload, ts \\ :os.system_time(:millisecond)) do
    secret_key = get_secret_key()

    with {:request_body, {:ok, request_body}} <- {:request_body, Request.make_encrypted_request_body(payload, secret_key, ts)},
         {:response, %Req.Response{status: 200, body: response_body}} <- {:response, post(request_body, path)},
         {:parsed_response, {:ok, parsed_response}} <- {:parsed_response, Response.decrypt_and_parse(response_body, secret_key)} do
      {:ok, parsed_response}
    else
      {:request_body, error} -> error
      {:parsed_response, error} -> error
      {:response, response} -> {:error, response}
    end
  end

  def post(payload, path) do
    base_url = Application.fetch_env!(:ex_uid2, :base_url)
    api_key = Application.fetch_env!(:ex_uid2, :api_key)

    Req.post!(base_url <> path, auth: {:bearer, api_key}, body: payload)
  end

  def get_secret_key() do
    Application.fetch_env!(:ex_uid2, :secret_key) |> :base64.decode()
  end
end
