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
    :ets.new(@table_name, [:named_table, {:read_concurrency, true}, :public])
    send(self(), :refresh)
    {:ok, %{fetch_keyring_attempts: 0}}
  end

  @impl GenServer
  def handle_info(:refresh, state) do
    case Api.Sharing.fetch_keyring() do
      {:ok, fresh_keyring} ->
        :ets.insert(@table_name, {@keyring, fresh_keyring})
        Process.send_after(self(), :refresh, @refresh_rate_ms)
        {:noreply, put_in(state.fetch_keyring_attempts, 0)}

      error ->
        nb_attempts = state.fetch_keyring_attempts
        # Exponential backoff maxes out at a 32 seconds interval
        retry_time_ms = 500 * round(:math.pow(2, min(nb_attempts, 6)))

        Logger.warning(
          "Failed to fetch keyring: #{inspect(error)}. Retrying in #{retry_time_ms} ms."
        )

        Process.send_after(self(), :refresh, retry_time_ms)
        {:noreply, put_in(state.fetch_keyring_attempts, nb_attempts + 1)}
    end
  end

  @spec decrypt_token(binary(), non_neg_integer()) :: {:ok, ExUid2.Uid2.t()} | {:error, any()}
  def decrypt_token(token, now_ms \\ :os.system_time(:millisecond)) do
    # TODO: validate keys (see encryption.py)
    case get_keyring() do
      {:ok, keyring} ->
        token
        |> :base64.decode()
        |> Encryption.decrypt_v2_token(keyring, now_ms)

      error ->
        error
    end
  end

  @spec get_keyring() :: {:ok, Keyring.t()} | {:error, :no_keyring_stored}
  defp get_keyring() do
    case :ets.lookup(@table_name, @keyring) do
      [{@keyring, keyring}] ->
        {:ok, keyring}

      [] ->
        {:error, :no_keyring_stored}
    end
  end
end
