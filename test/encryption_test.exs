defmodule Test.Encryption do
  use ExUnit.Case

  alias Test.Support.Utils
  alias ExUid2.Encryption

  test "V2 Tokens can be decrypted" do
    keyring = Utils.keyring()
    token = Utils.make_token(keyring, %{uid: Utils.phone_uid()})
    {:ok, %ExUid2.Uid2{uid: uid}} = Encryption.decrypt_token(token, keyring)

    assert uid == Utils.phone_uid()
  end

  test "Tokens that are urlsafe base64 encoded can be decoded" do
    keyring = Utils.keyring()
    token = Utils.make_token(keyring)

    expected_decrypted_token = Encryption.decrypt_token(token, keyring)

    url_safe_token =
      token
      |> :base64.decode()
      |> :base64.encode(%{mode: :urlsafe})

    decrypted_token = Encryption.decrypt_token(url_safe_token, keyring)

    assert match?(^expected_decrypted_token, decrypted_token)
  end
end
