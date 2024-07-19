defmodule ExUid2.Keyring do
  @moduledoc """
  Struct holding the keys periodically fetched from the UID2 operator server.

  Fields:

  * `:keys` - The list of available keys

  * `:info` - Other information provided via the UID2 operator server's `/v2/keys/sharing` endpoint
  """

  @type t :: %__MODULE__{
          keys: %{non_neg_integer() => __MODULE__.Key.t()},
          info: __MODULE__.Info.t()
        }

  defstruct [
    :keys,
    :info
  ]

  defmodule Key do
    @moduledoc """
    Struct holding the information for a given key.

    Fields:

    * `:activates_ms` - Time when the key becomes active (Unix timestamp in milliseconds)

    * `:created_ms` - Time when the key was created (Unix timestamp in milliseconds)

    * `:id` - The key's ID for lookups in the keyring

    * `:secret` - That key's secret that must be used to decrypt the UID2 tokens.

    * `keyset_id - Unknown
    """
    @type t :: %__MODULE__{
            activates_ms: non_neg_integer(),
            created_ms: non_neg_integer(),
            expires_ms: non_neg_integer(),
            id: non_neg_integer(),
            secret: binary(),
            keyset_id: non_neg_integer()
          }
    defstruct [
      :activates_ms,
      :created_ms,
      :expires_ms,
      :id,
      :secret,
      :keyset_id
    ]

    @spec new(map()) :: ExUid2.Keyring.Key.t()
    def new(key_map) do
      %__MODULE__{
        activates_ms: key_map["activates"],
        created_ms: key_map["created"],
        expires_ms: key_map["expires"],
        id: key_map["id"],
        secret: key_map["secret"] |> decode_secret(),
        keyset_id: key_map["keyset_id"]
      }
    end

    defp decode_secret(nil), do: nil
    defp decode_secret(encoded_secret), do: :base64.decode(encoded_secret)
  end

  defmodule Info do
    @moduledoc false
    @type t :: %__MODULE__{}
    defstruct [
      :identity_scope,
      :caller_site_id,
      :master_keyset_id,
      :site_data,
      :token_expiry_seconds
    ]

    def new(keyring_map) do
      %__MODULE__{
        identity_scope: keyring_map["identity_scope"],
        caller_site_id: keyring_map["caller_site_id"],
        master_keyset_id: keyring_map["master_keyset_id"],
        site_data: keyring_map["site_data"],
        token_expiry_seconds: keyring_map["token_expiry_seconds"]
      }
    end
  end

  @spec new(map()) :: ExUid2.Keyring.t()
  def new(%{"keys" => raw_keys} = keyring_map) when not is_nil(raw_keys) do
    keys =
      raw_keys
      |> Enum.map(fn raw_key -> Key.new(raw_key) end)
      |> Enum.map(fn key -> {key.id, key} end)
      |> Map.new()

    %__MODULE__{
      keys: keys,
      info: Info.new(keyring_map)
    }
  end

  @spec get_key(t(), non_neg_integer()) :: {:ok, Key.t()} | {:error, :key_not_found}
  def get_key(%__MODULE__{} = keyring, id) do
    case Map.get(keyring.keys, id) do
      nil ->
        {:error, :key_not_found}

      key ->
        {:ok, key}
    end
  end
end
