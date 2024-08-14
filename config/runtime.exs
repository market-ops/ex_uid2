import Config

if Mix.env() == :dev do
  uid2_base_url =
    System.get_env("UID2_BASE_URL") || raise "Missing UID2_BASE_URL environment variable"

  uid2_api_key =
    System.get_env("UID2_API_KEY") || raise "Missing UID2_API_KEY environment variable"

  uid2_secret_key =
    System.get_env("UID2_SECRET_KEY") || raise "Missing UID2_SECRET_KEY environment variable"

  config :ex_uid2,
    base_url: uid2_base_url,
    api_key: uid2_api_key,
    secret_key: uid2_secret_key
end
