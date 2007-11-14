require 'test/unit'
require 'oauth'

# This performs testing against Andy Smith's test server http://term.ie/oauth/example/
# Thanks Andy.
# This also means you have to be online to be able to run these.
class OAuthConsumerTest < Test::Unit::TestCase
  def setup
    @consumer=OAuth::Consumer.new( {
        :consumer_key=>"key",
        :consumer_secret=>"secret",
        :request_token=>"http://term.ie/oauth/example/request_token.php",
        :access_token=>"http://term.ie/oauth/example/access_token.php",
        :authorize=>"http://term.ie/oauth/example/authorize.php"
        })
  end
  
  def test_initializer
    assert_equal "key",@consumer.key
    assert_equal "secret",@consumer.secret
    assert_equal "http://term.ie/oauth/example/request_token.php",@consumer.request_token_path
    assert_equal "http://term.ie/oauth/example/access_token.php",@consumer.access_token_path
    assert_equal :post,@consumer.http_method
  end
  
  def test_get_token_sequence
    @request_token=@consumer.request_token
    assert_not_nil @request_token
    assert_equal "requestkey",@request_token.token
    assert_equal "requestsecret",@request_token.secret
    assert_equal "http://term.ie/oauth/example/authorize.php?oauth_token=requestkey",@request_token.authorize_url

    @access_token=@request_token.access_token
    assert_not_nil @access_token
    assert_equal "accesskey",@access_token.token
    assert_equal "accesssecret",@access_token.secret
    
    @response=@access_token.get("http://term.ie/oauth/example/echo_api.php",{:test=>"this",:ok=>"hello"})
    assert_not_nil @response
    assert_equal( "ok=hello&test=this",@response.body)
    
    @response=@access_token.post("http://term.ie/oauth/example/echo_api.php",{:test=>"this",:ok=>"hello"})
    assert_not_nil @response
    assert_equal( "ok=hello&test=this",@response.body)
    
  end
end
