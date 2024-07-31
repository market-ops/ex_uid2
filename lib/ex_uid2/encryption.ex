defmodule ExUid2.Encryption do
  @moduledoc """
  Module responsible for performing encryption and decryption of Uid2 tokens.
  """

  alias ExUid2.Encryption.EncryptedToken
  alias ExUid2.Encryption.Identity
  alias ExUid2.Encryption.MasterPayload
  alias ExUid2.Uid2
  alias ExUid2.Keyring

  @typedoc "Encryption error atom."
  @type encryption_error ::
   :base_64_decoding_error
   | :cannot_decrypt_payload
   | :invalid_master_payload
   | :invalid_v2_identity_payload
   | :invalid_v3_identity_payload
   | :no_keyring_stored
   | :not_authorized_for_master_key
   | :not_authorized_for_site_key
   | :token_expired

  @type secret_key :: <<_::256>>

  @spec decrypt_token(binary(), Keyring.t(), non_neg_integer()) :: {:ok, Uid2.t()} | {:error, encryption_error()}
  def decrypt_token(token_bin, keyring, now_ms \\ :os.system_time(:millisecond)) do
    with {:decoded_token, {:ok, decoded_token_bin}} <- {:decoded_token, decode_token(token_bin)},
         {:parsed_token, {:ok, token}} <- {:parsed_token, EncryptedToken.parse_token(decoded_token_bin)},
         {:master_key, {:ok, master_key}} <- {:master_key, Keyring.get_key(keyring, token.master_key_id)},
         {:master_payload, {:ok, master_payload}} <- {:master_payload, MasterPayload.decrypt(token, master_key)},
         {:expired?, false} <- {:expired?, now_ms > master_payload.expires_ms},
         {:site_key, {:ok, site_key}} <- {:site_key, Keyring.get_key(keyring, master_payload.site_key_id)},
         {:identity, {:ok, identity}} <- {:identity, Identity.decrypt(master_payload, site_key)} do
      %Identity{id_bin: id_bin, established_ms: established_ms, site_id: site_id} = identity
      %EncryptedToken{version: version, identity_type: identity_type} = token
      {:ok,
        %Uid2{
          uid: id_bin,
          established_ms: established_ms,
          site_id: site_id,
          site_key: site_key,
          identity_scope: keyring.info.identity_scope,
          identity_type: identity_type,
          version: version,
          expires_ms: master_payload.expires_ms
        }
      }
    else
      {:decoded_token, error} -> error
      {:parsed_token, error} -> error
      {:master_key, {:error, :key_not_found}} -> {:error, :not_authorized_for_master_key}
      {:master_payload, error} -> error
      {:expired?, true} -> {:error, :token_expired}
      {:site_key, {:error, :key_not_found}} -> {:error, :not_authorized_for_site_key}
      {:identity, error} -> error
    end
  end

  def encrypt_token(%Uid2{version: 2} = uid2, keyring, master_key_id, site_key_id), do: encrypt_v2_token(uid2, keyring, master_key_id, site_key_id)
  def encrypt_token(%Uid2{version: 3} = uid2, keyring, master_key_id, site_key_id), do: encrypt_v3_token(uid2, keyring, master_key_id, site_key_id)
  def encrypt_token(%Uid2{version: 4} = uid2, keyring, master_key_id, site_key_id), do: encrypt_v4_token(uid2, keyring, master_key_id, site_key_id)

  @spec encrypt_v2_token(Uid2.t(), Keyring.t(), non_neg_integer(), non_neg_integer()) :: {:ok, binary()}
  def encrypt_v2_token(uid2, keyring, master_key_id, site_key_id) do
    with {:site_key, {:ok, site_key}} <- {:site_key, Keyring.get_key(keyring, site_key_id)},
         {:master_key, {:ok, master_key}} <- {:master_key, Keyring.get_key(keyring, master_key_id)} do
    identity_iv = :crypto.strong_rand_bytes(16)
    %Uid2{uid: id_bin, expires_ms: expires_ms} = uid2
    identity = %Identity{version: 2, site_id: site_key_id, established_ms: 0, id_bin: id_bin, id_len: byte_size(id_bin)}
    encrypted_identity = Identity.encrypt(identity, site_key, identity_iv)

    master_payload = %MasterPayload{version: 2, site_key_id: site_key_id, identity_iv: identity_iv, identity_payload: encrypted_identity, expires_ms: expires_ms}
    master_iv = :crypto.strong_rand_bytes(16)
    encrypted_master_payload = MasterPayload.encrypt(master_payload, master_key, master_iv)
    encrypted_token = %EncryptedToken{version: 2, master_key_id: master_key_id, master_iv: master_iv, master_payload: encrypted_master_payload}

    token =
      encrypted_token
      |> EncryptedToken.make_v2_token_envelope()
      |> :base64.encode()

    {:ok, token}
    else
      {:site_key, _} -> {:error, :site_key_not_found}
      {:master_key, _} -> {:error, :master_key_not_found}
    end
  end

  @spec encrypt_v3_token(Uid2.t(), Keyring.t(), non_neg_integer(), non_neg_integer()) :: {:ok, binary()} | {:error, any()}
  def encrypt_v3_token(uid2, keyring, master_key_id, site_key_id) do
    case encrypt_v3(uid2, keyring, master_key_id, site_key_id) do
      {:ok, token} -> {:ok, :base64.encode(token)}
      {:error, _} = error -> error
    end
  end

  @spec encrypt_v4_token(Uid2.t(), Keyring.t(), non_neg_integer(), non_neg_integer()) :: {:ok, binary()} | {:error, any()}
  def encrypt_v4_token(uid2, keyring, master_key_id, site_key_id) do
    case encrypt_v3(uid2, keyring, master_key_id, site_key_id) do
      {:ok, token} -> {:ok, :base64.encode(token, %{mode: :urlsafe})}
      {:error, _} = error -> error
    end
  end

  defp encrypt_v3(uid2, keyring, master_key_id, site_key_id) do
    with {:site_key, {:ok, site_key}} <- {:site_key, Keyring.get_key(keyring, site_key_id)},
         {:master_key, {:ok, master_key}} <- {:master_key, Keyring.get_key(keyring, master_key_id)} do
      %Uid2{version: version, uid: id_bin, expires_ms: expires_ms, identity_type: identity_type} = uid2
      identity = %Identity{version: version, site_id: site_key_id, established_ms: 0, id_bin: id_bin}
      encrypted_identity = Identity.encrypt(identity, site_key)

      master_payload = %MasterPayload{version: version, site_key_id: site_key_id, identity_payload: encrypted_identity, expires_ms: expires_ms}
      encrypted_master_payload = MasterPayload.encrypt(master_payload, master_key)
      encrypted_token = %EncryptedToken{version: version, master_key_id: master_key_id, master_payload: encrypted_master_payload, identity_type: identity_type}
      {:ok, EncryptedToken.make_v3_token_envelope(encrypted_token)}
    else
      {:site_key, _} -> {:error, :site_key_not_found}
      {:master_key, _} -> {:error, :master_key_not_found}
    end
end

  defp decode_token(token_bin) do
    try do
      decoded =
        token_bin
        |> normalize_base64()
        |> :base64.decode(%{padding: false})
      {:ok, decoded}
    rescue
      _ ->
        {:error, :base_64_decoding_error}
    end
  end

  defp normalize_base64(bin) do
    bin
    |> String.replace("-", "+")
    |> String.replace("_", "/")
  end
end
