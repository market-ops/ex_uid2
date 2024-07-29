defmodule ExUid2.Encryption.EncryptedToken do
  @moduledoc false

  @type t :: %__MODULE__{
          version: non_neg_integer(),
          master_key_id: non_neg_integer(),
          master_iv: nil | <<_::128>>,
          master_payload: binary(),
          identity_type: nil | :phone | :email
        }

  defstruct [
    :version,
    :master_key_id,
    :master_payload,
    master_iv: nil,
    identity_type: nil
  ]

  @spec(parse_token(binary()) :: {:ok, t()}, {:error, :invalid_token})
  def parse_token(
        <<2::integer-8, master_key_id::big-integer-32, master_iv::big-binary-size(16),
          master_payload::binary>>
      ) do
    {:ok,
     %__MODULE__{
       version: 2,
       master_key_id: master_key_id,
       master_iv: master_iv,
       master_payload: master_payload
     }}
  end

  def parse_token(
        <<identity_type_int::integer-8, version::integer-8, master_key_id::big-integer-32,
          master_payload::binary>>
      ) do
    case parse_version(version) do
      {:ok, version} ->
        {:ok,
         %__MODULE__{
           version: version,
           identity_type: decode_identity_type_int(identity_type_int),
           master_key_id: master_key_id,
           master_payload: master_payload
         }}

      error ->
        error
    end
  end

  def make_v2_token_envelope(%__MODULE__{
        version: version,
        master_key_id: master_key_id,
        master_iv: master_iv,
        master_payload: master_payload
      }) do
    <<version::big-integer-8, master_key_id::big-integer-32, master_iv::big-binary-size(16),
      master_payload::binary>>
  end

  def make_v3_token_envelope(%__MODULE__{
        version: version,
        master_key_id: master_key_id,
        master_payload: master_payload,
        identity_type: identity_type
      }) do
    {:ok, encoded_version} = encode_version(version)
    identity_type_int = encode_identity_type_int(identity_type)

    <<identity_type_int::integer-8, encoded_version::integer-8, master_key_id::big-integer-32,
      master_payload::binary>>
  end

  defp encode_version(3), do: {:ok, 112}
  defp encode_version(4), do: {:ok, 128}
  defp encode_version(_), do: {:error, :invalid_version}

  defp parse_version(112), do: {:ok, 3}
  defp parse_version(128), do: {:ok, 4}
  defp parse_version(_), do: {:error, :invalid_version}

  defp decode_identity_type_int(int) do
    int
    |> Bitwise.band(0x0F)
    |> Bitwise.bsr(2)
    |> case do
      0 ->
        :email

      _ ->
        :phone
    end
  end

  defp encode_identity_type_int(:email), do: 0x03
  defp encode_identity_type_int(:phone), do: 0x07
end
