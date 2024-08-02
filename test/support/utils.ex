defmodule Test.Support.Utils do
  @moduledoc false
  require EEx
  EEx.function_from_file(:def, :render, "test/support/keyring.json.eex", [:opts])

  @default_key_params %{
    created: 0,
    activates: 0,
    expires: 0
  }

  @default_keyring_params %{
    status: "success",
    key1: @default_key_params,
    key2: @default_key_params
  }

  def keyring_json(opts \\ %{}) do
    keys_params = %{
      key1: Map.merge(@default_key_params, opts[:key1] || %{}),
      key2: Map.merge(@default_key_params, opts[:key2] || %{})
    }

    render_opts = Map.merge(@default_keyring_params, keys_params)
    render(render_opts)
  end

  def keyring(opts \\ make_keyring_opts()) do
    keyring_json(opts)
    |> Jason.decode!(objects: :maps)
    |> Map.get("body")
    |> ExUid2.Keyring.new()
  end

  def make_keyring_opts(now \\ :os.system_time(:millisecond)) do
    key_opts = %{expires: now + 10_000}
    %{key1: key_opts, key2: key_opts}
  end

  def make_token(keyring, opts \\ %{}) do
    default_token_opts = %{
      expires_ms: :os.system_time(:millisecond) + 10_000,
      uid: email_uid(),
      version: 2,
      identity_type: :email
    }

    opts = Map.merge(default_token_opts, opts)

    opts =
      case opts[:version] do
        2 ->
          opts

        _ ->
          uid = opts[:uid]
          decoded_uid = :base64.decode(uid)
          Map.put(opts, :uid, decoded_uid)
      end

    uid2 = ExUid2.Uid2.new(opts)

    {:ok, token} =
      ExUid2.Encryption.encrypt_token(uid2, keyring, 1, 2)

    token
  end

  def master_secret(),
    do:
      <<139, 37, 241, 173, 18, 92, 36, 232, 165, 168, 23, 18, 38, 195, 123, 92, 160, 136, 185, 40,
        91, 173, 165, 221, 168, 16, 169, 164, 38, 139, 8, 155>>

  def site_secret(),
    do:
      <<32, 251, 7, 194, 132, 154, 250, 86, 202, 116, 104, 29, 131, 192, 139, 215, 48, 164, 11,
        65, 226, 110, 167, 14, 108, 51, 254, 125, 65, 24, 23, 133>>

  def email_uid, do: "ywsvDNINiZOVSsfkHpLpSJzXzhr6Jx9Z/4Q0+lsEUvM="
  def phone_uid, do: "BFOsW2SkK0egqbfyiALtpti5G/cG+PcEvjkoHl56rEV8"
  def client_secret(), do: "ioG3wKxAokmp+rERx6A4kM/13qhyolUXIu14WN16Spo="

  def import_keyring(path) do
    path
    |> File.read!()
    |> Jason.decode!(objects: :maps)
    |> Map.get("body")
    |> ExUid2.Keyring.new()
  end

  def prepare_response(text) do
    secret_key = Application.fetch_env!(:ex_uid2, :secret_key) |> :base64.decode()
    iv = :crypto.strong_rand_bytes(12)
    encrypted_response = encrypt_and_wrap_response(text, iv, secret_key)
    Req.Test.stub(ExUid2.Dsp, &Plug.Conn.send_resp(&1, 200, encrypted_response))
  end

  def encrypt_response(payload, iv, secret_key) do
    wrapped_payload = <<0::8*8, 0::8*8, payload::binary>>

    result =
      :crypto.crypto_one_time_aead(:aes_256_gcm, secret_key, iv, wrapped_payload, <<>>, true)

    {:ok, result}
  end

  def encrypt_and_wrap_response(payload, iv, secret_key) do
    {:ok, {encrypted_payload, tag}} = encrypt_response(payload, iv, secret_key)

    <<iv::binary, encrypted_payload::binary, tag::binary>>
    |> :base64.encode()
  end

  def try_until_success(fun, timeout_ms \\ 5_000) do
    now = :os.system_time(:millisecond)
    try_until_success_or_deadline(fun, now + timeout_ms)
  end

  defp try_until_success_or_deadline(fun, deadline) do
    with {:passed_deadline, false} <-
           {:passed_deadline, :os.system_time(:millisecond) > deadline},
         {:fun_result, {:ok, _} = result} <- {:fun_result, fun.()} do
      result
    else
      {:passed_deadline, true} -> {:error, :timeout}
      {:fun_result, _} -> try_until_success_or_deadline(fun, deadline)
    end
  end
end
