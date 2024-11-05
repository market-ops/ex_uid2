# This benchmark test measures the time it takes to
# get a key from the keyring using different approaches.

{:ok, keyring_term_string} = File.read("benchmarks/uid2_keyring_randomized")

{keyring, []} = Code.eval_string(keyring_term_string)

# Setup full keyring in ets table
ets_table_name = :ets_keyring_test
ets_keyring_name = :ets_keyring_name
:ets.new(ets_table_name, [:named_table, {:read_concurrency, true}, :public])
:ets.insert(ets_table_name, {ets_keyring_name, keyring})

# Setup individual keys in ets table
keys = keyring.keys
key_ids = Map.keys(keys)
Enum.each(keys, fn {key, value} ->
  :ets.insert(ets_table_name, {key, value})
end)

# Setup full keyring in persistent term
:persistent_term.put(:keyring, keyring)

# Setup individual keys in persistent term
Enum.each(keys, fn {key, value} ->
  :persistent_term.put({:key, key}, value)
end)

# Setup individual {key, secret} pairs in Foil
{:ok, _} = :foil_app.start()
:ok = :foil.new(:keyring)

Enum.each(keys, fn {key, value} ->
  :foil.insert(:keyring, key, value.secret)
end)

:foil.load(:keyring)

get_keyring_ets_fun = fn key ->
  {:ok, keyring} =
    case :ets.lookup(ets_table_name, ets_keyring_name) do
      [{^ets_keyring_name, keyring}] ->
        {:ok, keyring}

      [] ->
        {:error, :no_keyring_stored}
    end
  ExUid2.Keyring.get_key(keyring, key)
end

get_key_ets_fun = fn key ->
  case :ets.lookup(ets_table_name, key) do
    [{^key, value}] ->
      {:ok, value}

    [] ->
      {:error, :key_not_stored}
  end
end

get_keyring_persistent_term_fun = fn key ->
  keyring = :persistent_term.get(:keyring)
  ExUid2.Keyring.get_key(keyring, key)
end

get_key_persistent_term_fun = fn key ->
  _key = :persistent_term.get({:key, key})
end

get_key_foil_fun = fn key ->
  {:ok, _key} = :foil.lookup(:keyring, key)
end

Benchee.run(
  %{
    "ets_full_keyring" => fn ->
      key = Enum.random(key_ids)
      get_keyring_ets_fun.(key)
    end,
    "ets_key" => fn ->
      key = Enum.random(key_ids)
      get_key_ets_fun.(key)
    end,
    "persistent_term_full_keyring" => fn ->
      key = Enum.random(key_ids)
      get_keyring_persistent_term_fun.(key)
    end,
    "persistent_term_key" => fn ->
      key = Enum.random(key_ids)
      get_key_persistent_term_fun.(key)
    end,
    "foil_key" => fn ->
      key = Enum.random(key_ids)
      get_key_foil_fun.(key)
    end,
  },
  time: 10,
  memory_time: 2
)
