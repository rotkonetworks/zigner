desc "Load ASC API Key information to use in subsequent lanes"
lane :load_asc_api_key do
  require 'openssl'

  # openssl 3.x on macos breaks OpenSSL::PKey::EC.new with "invalid curve name"
  # for apple .p8 keys. fastlane's Token.create calls EC.new internally, so we
  # monkey-patch it to fall back to the generic PKey.read which handles it fine.
  unless OpenSSL::PKey::EC.singleton_class.method_defined?(:_orig_new)
    OpenSSL::PKey::EC.singleton_class.alias_method(:_orig_new, :new)
    OpenSSL::PKey::EC.define_singleton_method(:new) do |*args, &block|
      begin
        _orig_new(*args, &block)
      rescue OpenSSL::PKey::ECError => e
        raise unless e.message.include?('invalid curve name') && args.size == 1 && args[0].is_a?(String)
        OpenSSL::PKey.read(args[0])
      end
    end
  end

  app_store_connect_api_key(
    key_id: ENV["ASC_KEY_ID"],
    issuer_id: ENV["ASC_ISSUER_ID"],
    key_content: ENV["ASC_KEY_BASE64"],
    is_key_content_base64: true,
    in_house: false
  )
end
