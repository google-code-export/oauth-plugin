module OAuth
  class Consumer<ConsumerCredentials
    # Create a new consumer instance by passing it a configuration hash:
    #
    #<pre> @consumer=OAuth::Consumer.new( {
    #    :consumer_key=>"key",
    #    :consumer_secret=>"secret",
    #    :request_token=>"http://term.ie/oauth/example/request_token.php",
    #    :access_token=>"http://term.ie/oauth/example/access_token.php",
    #    :authorize=>"http://term.ie/oauth/example/authorize.php"
    #    })</pre>
    #
    # Start the process by requesting a token
    #
    # <pre>@request_token=@consumer.request_token
    # session[:request_token]=@request_token
    # redirect_to @request_token.authorize_url</pre>
    #
    # When user returns create an access_token
    #
    # <pre>@access_token=@reques_token.access_token
    # @photos=@access_token.get('http://test.com/photos.xml')</pre>
    #
    #
    
    def initialize(params)
      super params[:consumer_key],params[:consumer_secret]
      @params=params
    end
    
    def http_method
      @http_method||=@params[:http_method]||:post
    end
    
    # Create a Request Token
    def request_token
      request=OAuth::Request.new(http_method,request_token_path,{:oauth_consumer_key=>self.key})
      response=request.perform_token_request(self.secret)
      OAuth::RequestToken.new(self,response[:oauth_token],response[:oauth_token_secret])
    end
    
    def request_token_path
      @params[:request_token]
    end
    
    def authorize_path
      @params[:authorize]
    end
    
    def access_token_path
      @params[:access_token]
    end
  end
end
