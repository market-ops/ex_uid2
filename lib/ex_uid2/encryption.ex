defmodule ExUid2.Encryption do
  alias ExUid2.Encryption.EncryptedToken
  alias ExUid2.Encryption.Identity
  alias ExUid2.Encryption.MasterPayload
  alias ExUid2.Uid2
  alias ExUid2.Keyring

  @spec decrypt_v2_token(binary(), Keyring.t(), integer()) :: Uid2.t() | {:error, any()}
  def decrypt_v2_token(
    token_bin,
    keyring,
    now_ms
  ) do
    with {:parsed_v2_token, {:ok, token}} <- {:parsed_v2_token, EncryptedToken.parse_v2_token(token_bin)},
         {:master_key, {:ok, master_key}} <- {:master_key, Keyring.get_key(keyring, token.master_key_id)},
         {:master_payload, {:ok, master_payload}} <- {:master_payload, MasterPayload.decrypt(token.master_payload, master_key, token.master_iv)},
         {:expired?, false} <- {:expired?, now_ms < master_payload.expires_ms},
         {:site_key, {:ok, site_key}} <- {:site_key, Keyring.get_key(keyring, master_payload.site_key_id)},
         {:identity, {:ok, identity}} <- {:identity, Identity.decrypt(master_payload.identity_payload, site_key, master_payload.identity_iv)} do
      {:ok,
       %Uid2{
        uid: identity.id_bin,
        established_ms: identity.established_ms,
        site_id: identity.site_id,
        site_key: site_key,
        identity_scope: keyring.info.identity_scope,
        identity_type: nil,
        advertising_token_version: token.version,
        expires_ms: master_payload.expires_ms
       }
      }
    else
      {:parsed_v2_token, error} -> error
      {:master_key, {:error, :key_not_found}} -> {:error, :not_authorized_for_master_key}
      {:master_payload, error} -> error
      {:expired?, true} -> {:error, :token_expired}
      {:site_key, {:error, :key_not_found}} -> {:error, :not_authorized_for_site_key}
      {:identity, error} -> error
    end
  end
end
