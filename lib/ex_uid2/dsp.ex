defmodule ExUid2.Dsp do
  alias ExUid2.Encryption
  alias ExUid2.Keyring
  alias ExUid2.Api
  use GenServer

  @table_name __MODULE__
  @keyring :uid2_decryption_keyring
  @refresh_rate_ms 5000

  def start_link(opts \\ []) do
    :ets.new(@table_name, [:named_table, {:read_concurrency, true}, :public])
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  def child_spec(_opts) do
    %{
      id: __MODULE__,
      start: {__MODULE__, :start_link, []}
    }
  end

  @impl GenServer
  def init(_opts) do
    send(self(), :refresh)
    {:ok, []}
  end

  @impl GenServer
  def handle_info(:refresh, state) do
    fresh_keyring = Api.Sharing.fetch_keyring()
    :ets.insert(@table_name, {@keyring, fresh_keyring})
    Process.send_after(self(), :refresh, @refresh_rate_ms)
    {:noreply, state}
  end

  @spec get_keyring() :: Keyring.t()
  def get_keyring() do
    [{@keyring, keyring}] = :ets.lookup(@table_name, @keyring)
    keyring
  end

  def decrypt_token(token, now_ms \\ :os.system_time(:millisecond)) do
    keyring = get_keyring()
    # TODO: validate keys (see encryption.py)

    token
    |> :base64.decode()
    |> Encryption.decrypt_v2_token(keyring, now_ms)
  end
end
