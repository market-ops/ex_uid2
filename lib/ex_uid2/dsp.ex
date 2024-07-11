defmodule ExUid2.Dsp do
  alias ExUid2.Encryption
  alias ExUid2.Keyring
  alias ExUid2.Api
  use GenServer

  @table_name __MODULE__
  @keyring :uid2_decryption_keyring
  @refresh_rate_ms 5000

  require Logger

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
    case Api.Sharing.fetch_keyring() do
      {:ok, fresh_keyring} ->
        :ets.insert(@table_name, {@keyring, fresh_keyring})
        Process.send_after(self(), :refresh, @refresh_rate_ms)

      error ->
        Logger.warning("Failed to fetch keyring: #{inspect(error)}. Retrying in one minute.")
        Process.send_after(self(), :refresh, 60_000)
    end

    {:noreply, state}
  end

  @spec decrypt_token(binary(), non_neg_integer()) :: ExUid2.Uid2.t() | {:error, any()}
  def decrypt_token(token, now_ms \\ :os.system_time(:millisecond)) do
    keyring = get_keyring()
    # TODO: validate keys (see encryption.py)

    token
    |> :base64.decode()
    |> Encryption.decrypt_v2_token(keyring, now_ms)
  end

  @spec get_keyring() :: Keyring.t()
  defp get_keyring() do
    [{@keyring, keyring}] = :ets.lookup(@table_name, @keyring)
    keyring
  end
end
