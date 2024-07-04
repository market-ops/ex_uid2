defmodule ExUid2.Encryption do
  alias ExUid2.Encryption.EncryptedToken
  alias ExUid2.Encryption.DecryptedIdentity
  alias ExUid2.Encryption.DecryptedMasterPayload
  alias ExUid2.Uid2
  alias ExUid2.Keyring

  @spec decrypt_v2_token(binary(), Keyring.t(), integer()) :: DecryptedToken.t() | {:error, any()}
  def decrypt_v2_token(
    token_bin,
    keyring,
    now_ms
  ) do
    with {:parsed_v2_token, {:ok, token}} <- {:parsed_v2_token, parse_v2_token(token_bin)},
         {:version, 2} <- {:version, token.version},
         {:master_key, {:ok, master_key}} <- {:master_key, Keyring.get_key(keyring, token.master_key_id)},
         {:decrypted_master_payload, decrypted_master_payload} <- {:decrypted_master_payload, decrypt(master_key, token.master_iv, token.master_payload)},
         {:parsed_master_payload, {:ok, master_payload}} <- {:parsed_master_payload, parse_master_payload(decrypted_master_payload)},
         {:expired?, false} <- {:expired?, now_ms < master_payload.expires_ms},
         {:site_key, {:ok, site_key}} <- {:site_key, Keyring.get_key(keyring, master_payload.site_key_id)},
         {:decrypted_identity, decrypted_identity} <- {:decrypted_identity, decrypt(site_key, master_payload.identity_iv, master_payload.identity_payload)},
         {:parse_identity, {:ok, identity}} <- {:parse_identity, parse_identity(decrypted_identity)} do
      %Uid2{
        uid: identity.id_bin,
        established: DateTime.from_unix!(identity.established_ms, :millisecond),
        site_id: identity.site_id,
        site_key: site_key,
        identity_scope: keyring.info.identity_scope,
        identity_type: nil,
        advertising_token_version: token.version,
        expires: DateTime.from_unix!(master_payload.expires_ms, :millisecond)
      }
    else
      {:version, _} -> {:error, :not_version_2}
      {:master_key, {:error, :key_not_found}} -> {:error, :not_authorized_for_master_key}
      {:parsed_master_payload, error} -> error
      {:site_key, {:error, :key_not_found}} -> {:error, :not_authorized_for_key}
      {:expired?, true} -> {:error, :token_expired}
    end
  end

  defp parse_v2_token(
    <<version::big-integer-8, master_key_id::big-integer-32, master_iv::big-binary-size(16),
          master_payload::binary>>
  ) do
    {:ok, %EncryptedToken{
      version: version,
      master_key_id: master_key_id,
      master_iv: master_iv,
      master_payload: master_payload
    }}
  end

  defp parse_v2_token(_) do
    {:error, :invalid_token}
  end

  defp parse_identity(
    <<site_id::big-integer-32, id_len::big-integer-32, id_bin::binary-size(id_len),
      _::binary-size(4), established_ms::big-integer-64, _::binary>>
  ) do
  {
    :ok,
    %DecryptedIdentity{
      site_id: site_id,
      id_len: id_len,
      id_bin: id_bin,
      established_ms: established_ms
    }
  }
  end

  defp parse_identity(_) do
    {:error, :invalid_identity}
  end

  defp parse_master_payload(
    <<expires_ms::big-integer-64, site_key_id::big-integer-32,
      identity_iv::big-binary-size(16), identity_payload::binary>>
    ) do
    {
      :ok,
      %DecryptedMasterPayload{
        expires_ms: expires_ms,
        site_key_id: site_key_id,
        identity_iv: identity_iv,
        identity_payload: identity_payload
      }
    }
  end

  defp parse_master_payload(_) do
    {:error, :invalid_master_payload}
  end

  defp decrypt(key, iv, payload) do
    :crypto.crypto_one_time(:aes_256_cbc, key.secret, iv, payload, false)
  end

end
