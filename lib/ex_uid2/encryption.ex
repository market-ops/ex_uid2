defmodule ExUid2.Encryption do
  alias ExUid2.Encryption.EncryptedToken
  alias ExUid2.Encryption.Identity
  alias ExUid2.Encryption.MasterPayload
  alias ExUid2.Uid2
  alias ExUid2.Keyring

  @type secret_key :: <<_::256>>

  @spec decrypt_v2_token(binary(), Keyring.t(), non_neg_integer()) :: {:ok, Uid2.t()} | {:error, any()}
  def decrypt_v2_token(
    token_bin,
    keyring,
    now_ms
  ) do
    with {:parsed_v2_token, {:ok, token}} <- {:parsed_v2_token, EncryptedToken.parse_v2_token(token_bin)},
         {:master_key, {:ok, master_key}} <- {:master_key, Keyring.get_key(keyring, token.master_key_id)},
         {:master_payload, {:ok, master_payload}} <- {:master_payload, MasterPayload.decrypt(token.master_payload, master_key, token.master_iv)},
         {:expired?, false} <- {:expired?, now_ms > master_payload.expires_ms},
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

  @spec encrypt_v2_token(binary(), Keyring.t(), non_neg_integer(), non_neg_integer(), non_neg_integer()) :: binary()
  def encrypt_v2_token(id_bin, keyring, master_key_id, site_key_id, expires_ms) do

    {:ok, site_key} = Keyring.get_key(keyring, site_key_id)
    identity_iv = :crypto.strong_rand_bytes(16)
    identity = %Identity{site_id: site_key_id, established_ms: 0, id_bin: id_bin, id_len: byte_size(id_bin)}
    encrypted_identity = Identity.encrypt(identity, site_key, identity_iv)

    {:ok, master_key} = Keyring.get_key(keyring, master_key_id)
    master_payload = %MasterPayload{site_key_id: site_key_id, identity_iv: identity_iv, identity_payload: encrypted_identity, expires_ms: expires_ms}
    master_iv = :crypto.strong_rand_bytes(16)
    encrypted_master_payload = MasterPayload.encrypt(master_payload, master_key, master_iv)
    encrypted_token = %EncryptedToken{version: 2, master_key_id: master_key_id, master_iv: master_iv, master_payload: encrypted_master_payload}

    EncryptedToken.make_v2_token_envelope(encrypted_token)
  end
end
