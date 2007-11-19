module OAuth
  
  # Superclass for the various tokens used by OAuth
  
  class Token
    include OAuth::Key
    
    attr_accessor :token, :secret

    def initialize(token, secret)
      @token = token
      @secret = secret
    end
    
    def to_query
      "oauth_token=#{escape(token)}&oauth_secret=#{escape(secret)}"
    end
    
  end
  
  # Used on the server for generating tokens
  class ServerToken<Token
    
    def initialize
      super generate_key(16),generate_key
    end
  end
  # Superclass for tokens used by OAuth Clients
  class ConsumerToken<Token
    attr_accessor :consumer

    def initialize(consumer,token,secret)
      super token,secret
      @consumer=consumer
    end
  end

  # The RequestToken is used for the initial Request.
  # This is normally created by the Consumer object.
  class RequestToken<ConsumerToken
    
    # Returns the authorization url that you need to use for redirecting the user
    def authorize_url
      consumer.authorize_path+"?oauth_token="+CGI.escape(token)
    end
    
    # exchange for AccessToken on server
    def access_token
      request=consumer.create_request(consumer.access_token_path,{:oauth_token=>self.token})
      response=request.perform_token_request(consumer.secret,self.secret)
      OAuth::AccessToken.new(consumer,response[:oauth_token],response[:oauth_token_secret])
    end
  end
  
  # The Access Token is used for the actual "real" web service calls thatyou perform against the server
  class AccessToken<ConsumerToken
    
    def get(url,params={},headers={})
      perform(:get,url,params,headers)
    end
    
    def head(url,params={},headers={})
      perform(:head,url,params,headers)
    end

    def post(url,params={},headers={})
      perform(:post,url,params,headers)
    end

    def put(url,params={},headers={})
      perform(:put,url,params,headers)
    end
    
    def delete(url,params={},headers={})
      perform(:delete,url,params,headers)
    end

    def perform(http_method,url,params={},headers={})
      request=OAuth::Request.new(http_method,url,params.merge({:oauth_consumer_key=>consumer.key,:oauth_token=>self.token}))
      response=request.perform(consumer.secret,self.secret)
    end
  end
end
