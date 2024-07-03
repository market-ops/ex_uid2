defmodule ExUid2.Dsp do
  alias ExUid2.Dsp.Keyring
  alias ExUid2.DecryptedToken
  use GenServer

  @table_name __MODULE__
  @keyring :uid2_decryption_keyring
  @refresh_rate_ms 5000

  def start_link(opts \\ []) do
    :ets.new(@table_name, [:named_table, {:read_concurrency, true}, :public])
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl GenServer
  def init(_opts) do
    send(self(), :refresh)
    {:ok, []}
  end

  @impl GenServer
  def handle_info(:refresh, state) do
    start_time = :os.system_time(:millisecond)

    fresh_keyring = fetch_keyring()
    :ets.insert(@table_name, {@keyring, fresh_keyring})

    stop_time = :os.system_time(:millisecond)

    next_refresh_in_ms = @refresh_rate_ms - (stop_time - start_time)
    Process.send_after(self(), :refresh, next_refresh_in_ms)

    {:noreply, state}
  end

  # TODO: figure the right specs for keys
  def get_keys() do
    [{@keyring, keys}] = :ets.lookup(@table_name, @keyring)
    keys
  end

  def decrypt_token(token) do
    keys = get_keys()
    decrypt_token(token, keys)
  end

  defp fetch_keyring() do
    path = "/v2/key/sharing"

    resp = ExUid2.Request.send(path, "")
    secret_key = Application.fetch_env!(:ex_uid2, :secret_key) |> :base64.decode()

    response =
      resp.body
      |> :base64.decode()
      |> ExUid2.Request.decrypt_response(secret_key)

    raw_body = Map.get(response, "body")

    ExUid2.Dsp.Keyring.new(raw_body)
  end

  def decrypt_token(token, keyring, ts \\ :os.system_time(:millisecond)) do
    # TODO: validate keys (see encryption.py)
    # decoded_token_bytes = :base64.decode(token_bytes_bin)
    # IO.inspect(decoded_token_bytes: decoded_token_bytes)
    # TODO: verify that token_bytes = 2 for v2

    decoded_token = :base64.decode(token)

    <<version::big-integer-8, _::binary>> = decoded_token

    case version do
      2 ->
        decrypt_v2_token(decoded_token, keyring, ts)

      _ ->
        {:error, :unsupported_version}
    end
  end

  defp decrypt(key, iv, payload) do
    :crypto.crypto_one_time(:aes_256_cbc, key.secret, iv, payload, false)
  end

  def decrypt_v2_token(
        <<version::big-integer-8, master_key_id::big-integer-32, master_iv::big-binary-size(16),
          master_payload::binary>> = _token,
        keyring,
        now
      ) do
    with {:master_key, {:ok, master_key}} <-
           {:master_key, Keyring.get_key(keyring, master_key_id)},
         {:decrypted_master_payload,
          <<expires_ms::big-integer-64, site_key_id::big-integer-32,
            identity_iv::big-binary-size(16),
            identity_payload::binary>> = decrypted_master_payload} <-
           {:decrypted_master_payload, decrypt(master_key, master_iv, master_payload)},
         {:site_key, {:ok, site_key}} <- {:site_key, Keyring.get_key(keyring, site_key_id)},
         {:decrypted_identity,
          <<site_id::big-integer-32, id_len::big-integer-32, id_bin::binary-size(id_len),
            _::binary-size(4), established_ms::big-integer-64,
            _::binary>> = decrypted_identity} <-
           {:decrypted_identity, decrypt(site_key, identity_iv, identity_payload)} do
      # TODO: see if I actually need to implement the site key logic
      # If I do, I need to build a lookup table that maps site_ids to keys
      # In the refresh token I got, there was no site_id fields anywhere.

      %DecryptedToken{
        status: :success,
        uid: id_bin,
        established: DateTime.from_unix!(established_ms, :millisecond),
        site_id: site_id,
        site_key: site_key,
        identity_scope: keyring.info.identity_scope,
        identity_type: nil,
        advertising_token_version: version,
        expires: DateTime.from_unix!(expires_ms, :millisecond)
      }
    else
      {:master_key, {:error, :key_not_found}} ->
        %DecryptedToken{status: :not_authorized_for_master_key}

      # {:expired, true} ->
      #   %DecryptedToken{status: :expired}
      {:site_key, {:error, :key_not_found}} ->
        %DecryptedToken{status: :not_authorized_for_key}

        # TODO: check for valid lifetime
    end
  end
end
