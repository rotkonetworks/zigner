desc "Load ASC API Key information to use in subsequent lanes"
lane :load_asc_api_key do
  require 'base64'
  require 'tempfile'

  key_file = Tempfile.new(['asc_key', '.p8'])
  key_file.write(Base64.decode64(ENV["ASC_KEY_BASE64"]))
  key_file.close

  app_store_connect_api_key(
    key_id: ENV["ASC_KEY_ID"],
    issuer_id: ENV["ASC_ISSUER_ID"],
    key_filepath: key_file.path,
    in_house: false
  )
end
