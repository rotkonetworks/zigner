desc "Load ASC API Key information to use in subsequent lanes"
lane :load_asc_api_key do
  require 'base64'
  require 'tempfile'

  # ruby's openssl 3.x bindings on macos can't parse apple .p8 keys
  # (PKCS8 EC format) — both EC.new and PKey.read fail with "invalid curve name".
  # convert PKCS8 → SEC1 EC format using the openssl CLI which handles it fine.
  raw = Base64.decode64(ENV["ASC_KEY_BASE64"])

  pkcs8 = Tempfile.new(['asc_key', '.p8'])
  pkcs8.binmode
  pkcs8.write(raw)
  pkcs8.close

  ec_pem = `openssl ec -in #{pkcs8.path} 2>/dev/null`
  pkcs8.unlink

  UI.user_error!("failed to convert ASC API key from PKCS8 to EC format") if ec_pem.strip.empty?

  app_store_connect_api_key(
    key_id: ENV["ASC_KEY_ID"],
    issuer_id: ENV["ASC_ISSUER_ID"],
    key_content: ec_pem,
    is_key_content_base64: false,
    in_house: false
  )
end
