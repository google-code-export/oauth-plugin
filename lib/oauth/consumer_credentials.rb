module OAuth
  class ConsumerCredentials
    attr_accessor :key, :secret

    def initialize(key, secret)
      @key = key
      @secret = secret
    end
  end
  
end
