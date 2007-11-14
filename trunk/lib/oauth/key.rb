require 'openssl'
require 'base64'
module OAuth
  module Key
    def generate_key(size=32)
      Base64.encode64(OpenSSL::Random.random_bytes(size)).gsub(/\W/,'')
    end
  end
end