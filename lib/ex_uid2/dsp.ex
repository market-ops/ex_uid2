defmodule ExUid2.Dsp do
  alias ExUid2.Encryption
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
        Encryption.decrypt_v2_token(decoded_token, keyring, ts)

      _ ->
        {:error, :unsupported_version}
    end
  end



end
