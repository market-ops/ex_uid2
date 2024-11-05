defmodule ExUid2.MixProject do
  use Mix.Project

  @source_url "https://github.com/market-ops/ex_uid2"
  @version "0.2.2"

  def project do
    [
      app: :ex_uid2,
      version: @version,
      elixir: "~> 1.15",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      docs: docs(),
      description: description(),
      package: package(),
      aliases: aliases(),
      source_url: @source_url,
      dialyzer: [
        plt_add_apps: [:mix]
      ]
    ]
  end

  def application do
    [
      extra_applications: [:logger],
      mod: {ExUid2.Application, []}
    ]
  end

  defp deps do
    [
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:ex_doc, "~> 0.34", only: [:dev], runtime: false},
      {:req, "~> 0.5"},
      {:plug, "~> 1.16", only: [:test], runtime: false},
      {:benchee, "~> 1.3.1", only: :bench},
      {:foil, git: "https://github.com/lpgauth/foil.git", tag: "0.1.3", only: :bench}
    ]
  end

  defp aliases do
    [
      test: ["test --no-start"]
    ]
  end

  defp description do
    """
    UID2 Library for Elixir
    """
  end

  defp docs do
    [
      extras: ["README.md"],
      main: "readme",
      source_url: @source_url,
      source_ref: "v#{@version}",
      groups_for_modules: [
        Bucketing: [~r/Peep.Buckets/]
      ]
    ]
  end

  defp package do
    [
      maintainers: ["Fabien Lamarche-Filion"],
      licenses: ["Apache-2.0"],
      links: %{"GitHub" => @source_url}
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]
end
