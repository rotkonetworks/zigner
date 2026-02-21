desc "Load ASC API Key information to use in subsequent lanes"
lane :load_asc_api_key do
  %w[ASC_KEY_ID ASC_ISSUER_ID ASC_KEY_BASE64].each do |var|
    UI.user_error!("Missing secret: #{var} — set it in repo Settings → Secrets") if ENV[var].to_s.empty?
  end

  app_store_connect_api_key(
    key_id: ENV["ASC_KEY_ID"],
    issuer_id: ENV["ASC_ISSUER_ID"],
    key_content: ENV["ASC_KEY_BASE64"],
    is_key_content_base64: true,
    in_house: false
  )
end
