defmodule ExUid2.Encryption.EncryptedToken do
  @moduledoc false

  @type t :: %__MODULE__{
          version: non_neg_integer(),
          master_key_id: non_neg_integer(),
          master_iv: <<_::128>>,
          master_payload: binary()
        }

  defstruct [
    :version,
    :master_key_id,
    :master_iv,
    :master_payload
  ]

  @spec parse_v2_token(binary()) ::
          {:error, :invalid_v2_token} | {:ok, t()}
  def parse_v2_token(
        <<version::big-integer-8, master_key_id::big-integer-32, master_iv::big-binary-size(16),
          master_payload::binary>>
      )
      when version == 2 do
    {:ok,
     %__MODULE__{
       version: version,
       master_key_id: master_key_id,
       master_iv: master_iv,
       master_payload: master_payload
     }}
  end

  def parse_v2_token(_), do: {:error, :invalid_v2_token}

  def make_v2_token_envelope(%__MODULE__{
        version: version,
        master_key_id: master_key_id,
        master_iv: master_iv,
        master_payload: master_payload
      }) do
    <<version::big-integer-8, master_key_id::big-integer-32, master_iv::big-binary-size(16),
      master_payload::binary>>
  end
end
