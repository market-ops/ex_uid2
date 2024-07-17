defmodule ExUid2.Application do
  @moduledoc false
  use Application

  @impl true
  def start(_type, _args) do
    children = [ExUid2.Dsp]

    opts = [strategy: :one_for_one, name: ExUid2.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
