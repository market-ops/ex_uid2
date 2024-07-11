defmodule ExUid2.Api.Sharing do
  @moduledoc """
  This module provides the interface for the DSP to access the UID2 Operator Services's key sharing endpoint.
  """
  alias ExUid2.Api
  alias ExUid2.Keyring

  @key_sharing_path "/v2/key/sharing"

  @doc """
  Request the decryption keys necessary to decrypt UID2 tokens.
  """
  def fetch_keyring() do
    {:ok, resp} = Api.post_encrypted_request(@key_sharing_path, "")
    raw_keyring_map = Map.get(resp, "body")
    Keyring.new(raw_keyring_map)
  end
end