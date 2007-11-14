module OAuth
  # This will likely all change
  class Server
    include OAuth::Key
    
    @@server_paths={
      :request_token=>"/oauth/request_token",
      :authorize=>"/oauth/authorize",
      :access_token=>"/oauth/access_token"
    }
    # Create a new server instance
    def initialize(paths={})
      @paths=@@server_paths.merge(paths)
    end
    
    #override this
    def consumers
      @consumers||={}
    end
    
    def generate_consumer_credentials()
      [generate_key(16),generate_key]
    end
    
    def create_consumer(params={})
      consumer=ConsumerCredentials.new( *generate_consumer_credentials)
      consumers[consumer.key]=consumer
    end
    
    def register_consumer(params={})
      consumer=create_consumer(params)
      @paths.merge({:consumer_key=>consumer.key,:consumer_secret=>consumer.secret})
    end
    
    def request_token_path
      @paths[:request_token]
    end
    
    def authorize_path
      @paths[:authorize]
    end
    
    def access_token_path
      @paths[:access_token]
    end
    
  end
end
