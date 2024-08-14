defmodule ExUid2.Api.Bidstream do
  @moduledoc """
  This module provides the interface for the DSP to access the UID2 Operator Services's key bidstream endpoint.
  """
  alias ExUid2.Api
  alias ExUid2.Keyring

  @bidstream_path "/v2/key/bidstream"

  @doc """
  Request the decryption keys necessary to decrypt UID2 tokens.
  """
  @spec fetch_keyring() :: {:ok, Keyring.t()} | {:error, any()}
  def fetch_keyring() do
    case Api.post_encrypted_request(@bidstream_path, "") do
      {:ok, %{"status" => "success", "body" => body}} ->
        {:ok, Keyring.new(body)}

      {:ok, response} ->
        {:error, {:unexpected_response, response}}

      error ->
        error
    end
  end
end
