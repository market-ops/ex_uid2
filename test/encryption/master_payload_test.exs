defmodule Test.Encryption.MasterPayload do
  use ExUnit.Case

  alias ExUid2.Encryption.MasterPayload
  alias ExUid2.Encryption.EncryptedToken

  test "Invalid V3 Tokens return an error when they can't be parsed" do
    key = "fake_key"

    master_payload =
      "invalid" |> Base.encode64()

    token = %EncryptedToken{version: 3, master_payload: master_payload}

    {:error, :cannot_parse_encrypted_master_payload} = MasterPayload.decrypt(token, key)
  end
end
