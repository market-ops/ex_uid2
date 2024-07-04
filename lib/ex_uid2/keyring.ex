defmodule ExUid2.Dsp.Keyring do
  defstruct [
    :keys,
    :info
  ]

  defmodule Key do
    defstruct [
      :activates,
      :created,
      :expires,
      :id,
      :secret,
      :keyset_id
    ]

    def new(key_map) do
      %__MODULE__{
        activates: key_map["activates"],
        created: key_map["created"],
        expires: key_map["expires"],
        id: key_map["id"],
        secret: key_map["secret"] |> :base64.decode(),
        keyset_id: key_map["keyset_id"]
      }
    end
  end

  defmodule Info do
    defstruct [
      :identity_scope,
      :caller_site_id,
      :master_keyset_id,
      :site_data,
      :token_expiry_seconds
    ]
  end

  def new(%{"keys" => raw_keys} = keys_map) when not is_nil(raw_keys) do
    keys = Enum.map(raw_keys, fn raw_key -> Key.new(raw_key) end)

    %__MODULE__{
      keys: keys,
      info: %Info{
        identity_scope: keys_map["identity_scope"],
        caller_site_id: keys_map["caller_site_id"],
        master_keyset_id: keys_map["master_keyset_id"],
        site_data: keys_map["site_data"],
        token_expiry_seconds: keys_map["token_expiry_seconds"]
      }
    }
  end

  def get_key(%__MODULE__{} = keyring, id) do
    case Enum.find(keyring.keys, nil, fn key -> key.id == id end) do
      nil ->
        {:error, :key_not_found}

      key ->
        {:ok, key}
    end
  end
end