desc "Load ASC API Key information to use in subsequent lanes"
lane :load_asc_api_key do
  require 'base64'
  require 'tempfile'

  # ruby's openssl 3.x bindings on macos can't parse apple .p8 keys
  # (PKCS8 EC format) — EC.new fails with "invalid curve name".
  # convert PKCS8 → SEC1 EC format using the openssl CLI.
  raw = Base64.decode64(ENV["ASC_KEY_BASE64"])

  keyfile = Tempfile.new(['asc_key', '.p8'])
  keyfile.binmode
  keyfile.write(raw)
  keyfile.close

  is_pem = raw.start_with?("-----")
  inform = is_pem ? "PEM" : "DER"
  UI.message("ASC key format: #{inform}, size: #{raw.size} bytes")

  # try openssl ec, then openssl pkey as fallback
  ec_pem = `openssl ec -in #{keyfile.path} -inform #{inform} 2>&1`
  if !$?.success?
    UI.message("openssl ec failed: #{ec_pem.lines.first}")
    ec_pem = `openssl pkey -in #{keyfile.path} -inform #{inform} 2>&1`
    if !$?.success?
      UI.message("openssl pkey also failed: #{ec_pem.lines.first}")
      # last resort: try to use ruby's openssl with the raw key directly
      keyfile.unlink
      UI.user_error!("cannot convert ASC API key — check ASC_KEY_BASE64 secret format")
    end
  end

  keyfile.unlink

  # strip any stderr noise (e.g. "read EC key")
  ec_pem = ec_pem.lines.select { |l| l.match?(/^-----|\A[A-Za-z0-9+\/=]/) }.join

  app_store_connect_api_key(
    key_id: ENV["ASC_KEY_ID"],
    issuer_id: ENV["ASC_ISSUER_ID"],
    key_content: ec_pem,
    is_key_content_base64: false,
    in_house: false
  )
end
