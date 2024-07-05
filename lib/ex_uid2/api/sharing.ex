defmodule ExUid2.Api.Sharing do
  @moduledoc """
  This module provides the interface for the DSP to access the UID2 Operator Services's key sharing endpoint.
  """
  alias ExUid2.Api.Request
  alias ExUid2.Keyring

  @key_sharing_path "/v2/key/sharing"

  @doc """
  Request the decryption keys necessary to decrypt UID2 tokens.
  """
  def fetch_keyring() do
    resp = Request.post_encrypted_request(@key_sharing_path, "")
    # secret_key = Application.fetch_env!(:ex_uid2, :secret_key) |> :base64.decode()

    IO.inspect(resp: resp)

    # response =
    #   resp.body
    #   |> :base64.decode()
    #   |> Request.decrypt_response(secret_key)

    # raw_body = Map.get(response, "body")
    raw_body = Map.get(resp, "body")


    Keyring.new(raw_body)
  end

end
