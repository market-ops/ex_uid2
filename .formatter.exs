[
  inputs:
    Enum.flat_map(
      ["{mix,.formatter}.exs", "{config,lib,test}/**/*.{ex,exs}"],
      &Path.wildcard(&1, match_dot: true)
    ) --
      [
        "lib/ex_uid2/encryption.ex",
        "lib/ex_uid2/api.ex",
        "lib/ex_uid2/api/request.ex",
        "lib/ex_uid2/api/response.ex"
      ]
]
