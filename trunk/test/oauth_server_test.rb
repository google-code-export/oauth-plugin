require 'test/unit'
require 'oauth'
class OAuthServerTest < Test::Unit::TestCase
  def setup
    @server=OAuth::Server.new
  end
  
  def test_default_paths
    assert_equal "/oauth/request_token",@server.request_token_path
    assert_equal "/oauth/authorize",@server.authorize_path
    assert_equal "/oauth/access_token",@server.access_token_path
  end
  
  def test_generate_consumer_credentials
    key,secret =@server.generate_consumer_credentials
    assert_not_nil key
    assert_not_nil secret
  end

  def test_create_consumer
    @consumer=@server.create_consumer
    assert_not_nil @consumer
    assert_not_nil @consumer.key
    assert_not_nil @consumer.secret
    assert_equal @consumer,@server.consumers[@consumer.key]
  end


  def test_register_consumer
    @consumer_info=@server.register_consumer
    assert_not_nil @consumer_info
    assert_not_nil @consumer_info[:consumer_key]
    assert_not_nil @consumer_info[:consumer_secret]
    assert_equal "/oauth/request_token", @consumer_info[:request_token]
    assert_equal "/oauth/authorize", @consumer_info[:authorize]
    assert_equal "/oauth/access_token", @consumer_info[:access_token]
    
    assert_equal @consumer_info[:consumer_secret],@server.consumers[ @consumer_info[:consumer_key]].secret
  end
  
  
end
