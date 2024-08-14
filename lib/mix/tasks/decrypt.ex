defmodule Mix.Tasks.Decrypt do
  @moduledoc """
  A mix task to decrypt uid2 tokens from the shell: `mix decrypt <token>`
  """
  use Mix.Task

  @shortdoc "Decrypts a UID2 token."

  @impl Mix.Task
  def run(args) do
    [token] = args
    Mix.Task.run("app.start")
    ExUid2.Dsp.refresh()

    ExUid2.Dsp.decrypt_token(token)
    |> inspect()
    |> Mix.Shell.IO.info()
  end
end
