defmodule Test.Dsp do
  use ExUnit.Case

  alias Test.Support.Utils
  alias ExUid2.Dsp

  test "When started, the dsp client can decrypt a token" do
    now = :os.system_time(:millisecond)
    opts = make_opts(now)

    prepare_dsp(opts)
    Dsp.refresh()

    keyring = Utils.keyring(opts)
    token = make_token(keyring)

    {:ok, expected_uid2} = ExUid2.Encryption.decrypt_v2_token(token, keyring, now)

    {:ok, uid2} = Utils.try_until_success(fn -> Dsp.decrypt_token(token) end)

    assert match?(^expected_uid2, uid2)
  end

  test "When started, the dsp client will return an error if an attempt to decrypt the token is made before the keyring is fetched" do
    now = :os.system_time(:millisecond)
    opts = make_opts(now)

    prepare_dsp(opts)

    keyring = Utils.keyring(opts)
    token = make_token(keyring)

    result = Dsp.decrypt_token(token)

    assert match?({:error, :no_keyring_stored}, result)
  end

  test "Failed attempts to call the UID2 operator server will be retried" do
    now = :os.system_time(:millisecond)
    opts = make_opts(now)

    prepare_dsp(opts)

    Req.Test.expect(ExUid2.Dsp, &Req.Test.transport_error(&1, :econnrefused))
    Req.Test.expect(ExUid2.Dsp, &Plug.Conn.send_resp(&1, 500, "internal server error"))

    Dsp.start_refresh_loop()

    keyring = Utils.keyring(opts)
    token = make_token(keyring)

    {:ok, expected_uid2} = ExUid2.Encryption.decrypt_v2_token(token, keyring, now)

    {:ok, uid2} = Utils.try_until_success(fn -> Dsp.decrypt_token(token) end)

    assert match?(^expected_uid2, uid2)
  end

  defp make_opts(now) do
    key_opts = %{expires: now + 10_000}
    %{key1: key_opts, key2: key_opts}
  end

  defp make_token(keyring, expires_ms \\ :os.system_time(:millisecond) + 10_000) do
    {:ok, token} =
      ExUid2.Encryption.encrypt_v2_token(Utils.email_uid(), keyring, 1, 2, expires_ms)

    token
  end

  defp prepare_dsp(opts) do
    keyring_text = Utils.keyring_json(opts)
    Utils.prepare_response(keyring_text)
    {:ok, pid} = Dsp.start_link(mode: :passive)
    Req.Test.allow(ExUid2.Dsp, self(), pid)
  end
end
