defmodule ExUid2.Dsp do
  @moduledoc """
  This is the client module for DSP-side decryption of UID2 tokens.

  By default, when the `ExUid2` application starts, the `ExUid2.Dsp` server is started
  with the `:active` mode, which refreshes the keyring every hour.

  To manually control the keyring refresh calls, set the application
  with the `runtime: false` option and start the `ExUid2.Dsp` server
  with `ExUid2.Dsp.start_link(mode: :passive)`. Then, calling
  `ExUid2.Dsp.refresh/0` will make the query and refresh the keyring.
  """

  alias ExUid2.Encryption
  alias ExUid2.Keyring
  alias ExUid2.Api
  use GenServer

  @table_name __MODULE__
  @keyring :uid2_decryption_keyring
  @refresh_rate_ms 3_600_000

  @default_opts [mode: :active]

  require Logger

  @doc """
  Attempts to decrypt a base64 encoded UID2 token.

  ## Example
      iex> ExUid2.Dsp.decrypt("A3AAAAABI2RPtp1P7Fa66cRLOHzi2gkK2kxIEWpwX+cWgsLITmLS+/q7kHCuHMPhtweLapy0p8IXaR6T4eGlF3iloOSwzPaJ+PMUiRwdLVb8perCP4AmlnPeAlndOGAJNTlaSvqb1tUdUJwpOzkQv6yjE9LoLUT/82QhKt92WIehEdSjJm/YpSgLdMWazqXPzyJjTZ+GIgJn2k6qHb33AGoe5YSrrkp91xWL2H6Ziw==")
      {:ok,
        %ExUid2.Uid2{
          uid: "ywsvDNINiZOVSsfkHpLpSJzXzhr6Jx9Z/4Q0+lsEUvM=",
          established_ms: 0,
          site_id: 2,
          site_key: %ExUid2.Keyring.Key{
            activates_ms: 0,
            created_ms: 0,
            expires_ms: 1722448017227,
            id: 2,
            secret: <<32, 251, 7, 194, 132, 154, 250, 86, 202, 116, 104, 29, 131, 192,
              139, 215, 48, 164, 11, 65, 226, 110, 167, 14, 108, 51, 254, 125, 65, 24,
              23, 133>>,
            keyset_id: nil
          },
          identity_scope: "UID2",
          version: 3,
          expires_ms: 1722448110794,
          identity_type: :email
        }}
  """
  @spec decrypt_token(binary(), non_neg_integer()) ::
          {:ok, ExUid2.Uid2.t()} | {:error, Encryption.encryption_error()}
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

  @doc """
  Triggers a query to the Uid2 opperator server to get the latest keyring. Not required when the Dsp server is
  started in `:active` mode (which is the default) or when `ExUid2.Dsp.start_refresh_loop/0` has been called.
  """

  @spec refresh() :: :ok | {:error, any()}
  def refresh() do
    GenServer.call(__MODULE__, :refresh)
  end

  @doc """
  Starts hourly refreshing of the Keyring.

  When the `ExUid2.Dsp` server is started with `mode: :passive`, it won't periodically query the Uid2 operator server to
  refresh the keyring. Calling `ExUid2.Dsp.start_refresh_loop/0` will refresh the keyring and make the `ExUid2.Dsp` server
  refresh it again every hour.
  """
  def start_refresh_loop() do
    pid = GenServer.whereis(__MODULE__)
    send(pid, :refresh)
  end

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
