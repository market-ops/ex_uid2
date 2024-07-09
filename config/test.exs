import Config

config :ex_uid2,
  base_url: "http://fake_url.com",
  api_key: "fake_api_key",
  secret_key: "i+R/UarIyFhvCvihH4gyOe0Xwf2mpUSBxM1SXAuph/I=",
  req_opts: [
    plug: {Req.Test, ExUid2.Dsp}
  ]
