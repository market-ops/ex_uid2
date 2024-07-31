defmodule Test.Api.SharingTest do
  use ExUnit.Case, async: true

  alias ExUid2.Api.Sharing
  alias Test.Support.Utils

  test "fetch_keyring/0 sends the encrypted request, decrypts the response and parses the keyring " do
    keyring_opts = Utils.make_keyring_opts()

    keyring_text = Utils.keyring_json(keyring_opts)
    Utils.prepare_response(keyring_text)

    {:ok, keyring} = Sharing.fetch_keyring()

    expected_keyring = Utils.keyring(keyring_opts)
    assert match?(^expected_keyring, keyring)
  end

  test "fetch_keyring/0 returns an error if the request fails" do
    Req.Test.expect(ExUid2.Dsp, &Plug.Conn.send_resp(&1, 500, "internal server error"))
    response = Sharing.fetch_keyring()
    assert match?({:error, %Req.Response{status: 500}}, response)
  end

  test "fetch_keyring/0 returns an error if the request returns an unexpected object" do
    invalid_text = ~S'{"wrong":"format"}'
    Utils.prepare_response(invalid_text)

    response = Sharing.fetch_keyring()
    assert match?({:error, {:unexpected_response, _}}, response)
  end
end
