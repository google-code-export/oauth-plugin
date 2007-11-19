module OAuth
  # This will likely all change
  class Server
    include OAuth::Key
    attr_accessor :base_url
    
    @@server_paths={
      :request_token=>"/oauth/request_token",
      :authorize=>"/oauth/authorize",
      :access_token=>"/oauth/access_token"
    }
    # Create a new server instance
    def initialize(base_url,paths={})
      @base_url=base_url
      @paths=@@server_paths.merge(paths)
    end
        
    def generate_credentials()
      [generate_key(16),generate_key]
    end
    
    def generate_consumer_credentials(params={})
      ConsumerCredentials.new( *generate_credentials)
    end

    def create_consumer(params={})
      credentials=generate_credentials
      Consumer.new( {
        :consumer_key=>credentials[0],
        :consumer_secret=>credentials[1],
        :request_token=>request_token_url,
        :authorize=>authorize_url,
        :access_token=>access_token_url
      })
    end
        
    def request_token_path
      @paths[:request_token]
    end
    
    def request_token_url
      base_url+request_token_path
    end
    
    def authorize_path
      @paths[:authorize]
    end
    
    def authorize_url
      base_url+authorize_path
    end
    
    def access_token_path
      @paths[:access_token]
    end

    def access_token_url
      base_url+access_token_path
    end
    
    
  end
end
