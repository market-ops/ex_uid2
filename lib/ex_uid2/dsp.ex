defmodule ExUid2.Dsp do
  @moduledoc """
  This is the client module for DSP-side decryption of UID2 tokens.
  """

  alias ExUid2.Encryption
  alias ExUid2.Keyring
  alias ExUid2.Api
  use GenServer

  @table_name __MODULE__
  @keyring :uid2_decryption_keyring
  @refresh_rate_ms 5000

  @default_opts [mode: :active]

  require Logger

  def start_link(opts \\ []) do
    genserver_opts = Keyword.merge(@default_opts, opts)
    GenServer.start_link(__MODULE__, genserver_opts, name: __MODULE__)
  end

  def child_spec(_opts) do
    %{
      id: __MODULE__,
      start: {__MODULE__, :start_link, []}
    }
  end

  @impl GenServer
  def init(opts) do
    :ets.new(@table_name, [:named_table, {:read_concurrency, true}, :public])

    if opts[:mode] == :active do
      send(self(), :refresh)
    end

    {:ok, %{fetch_keyring_attempts: 0}}
  end

  def refresh() do
    GenServer.call(__MODULE__, :refresh)
  end

  def start_refresh_loop() do
    pid = GenServer.whereis(__MODULE__)
    send(pid, :refresh)
  end

  @impl GenServer
  def handle_call(:refresh, _from, state) do
    result = refresh_keyring()
    {:reply, result, state}
  end

  @impl GenServer
  def handle_info(:refresh, state) do
    case refresh_keyring() do
      :ok ->
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

  @doc """
  Attempts to decrypt a base64 encoded token.
  """
  @spec decrypt_token(binary(), non_neg_integer()) :: {:ok, ExUid2.Uid2.t()} | {:error, any()}
  def decrypt_token(token, now_ms \\ :os.system_time(:millisecond)) do
    # TODO: validate keys
    case get_keyring() do
      {:ok, keyring} ->
        token
        |> Encryption.decrypt_token(keyring, now_ms)

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

  defp refresh_keyring() do
    case Api.Sharing.fetch_keyring() do
      {:ok, fresh_keyring} ->
        :ets.insert(@table_name, {@keyring, fresh_keyring})
        :ok

      error ->
        error
    end
  end
end
