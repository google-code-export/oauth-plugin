require 'test/unit'
require 'action_controller'
require 'action_controller/test_process'
require 'oauth'
class OAuthRequestTest < Test::Unit::TestCase
  def setup
    @request=OAuth::Request.new( :get,'http://test.COM:80/oauth?stuff=1&picture=test.png', {:oauth_field1=>"test",:oauth_field2=>"hello",'string_key'=>"should be set"})
  end
  
  def test_accessors
    #as symbols
    assert_equal @request[:oauth_field1],"test"
    assert_equal @request[:oauth_field2],"hello"
    assert_equal @request[:string_key],"should be set"    
    assert_equal @request[:oauth_signature_method],"HMAC-SHA1"    
    #as strings
    assert_equal @request['oauth_field1'],"test"
    assert_equal @request['oauth_field2'],"hello"
    assert_equal @request['string_key'],"should be set"    
  end
  
  def test_to_query
    assert_equal "oauth_field1=test&oauth_field2=hello&oauth_nonce=#{URI.escape(@request.nonce)}&oauth_signature_method=HMAC-SHA1&oauth_timestamp=#{@request.timestamp}&oauth_version=1.0&picture=test.png&string_key=should%20be%20set&stuff=1",@request.to_query
  end

  def test_to_auth_string
    assert_equal "oauth_field1=test, oauth_field2=hello, oauth_nonce=#{URI.escape(@request.nonce)}, oauth_signature_method=HMAC-SHA1, oauth_timestamp=#{@request.timestamp}, oauth_version=1.0, string_key=should%20be%20set",@request.to_auth_string
  end
  
  def test_has_http_method
    assert_equal "GET",@request.http_method
  end

  def test_url_normalization
    #should remove port 80 from http
    assert_equal "http://test.com:80/oauth?stuff=1&picture=test.png",@request.url
    assert_equal "http://test.com/oauth",@request.normalized_url

    # should not have port
    @request.url="http://test.com/oauth"
    assert_equal "http://test.com/oauth",@request.url
    assert_equal "http://test.com/oauth",@request.normalized_url
    
    #should remove port 443 from https
    @request.url="https://test.com:443/oauth"
    assert_equal "https://test.com:443/oauth",@request.url
    assert_equal "https://test.com/oauth",@request.normalized_url
    
    #should retain port number
    @request.url="https://test.com:11822/oauth"
    assert_equal "https://test.com:11822/oauth",@request.url
    assert_equal "https://test.com:11822/oauth",@request.normalized_url
    
    # should retain port 80 on https
    @request.url="https://test.com:80/oauth"
    assert_equal "https://test.com:80/oauth",@request.url
    assert_equal "https://test.com:80/oauth",@request.normalized_url

    # should retain port 443 on http
    @request.url="http://test.com:443/oauth"
    assert_equal "http://test.com:443/oauth",@request.url
    assert_equal "http://test.com:443/oauth",@request.normalized_url
    
  end

  def test_has_nonce
    assert_not_nil @request.nonce
  end

  def test_has_timestamp
    assert_not_nil @request.timestamp
  end
  
  def test_not_signed
    assert !@request.signed?
  end

  def test_has_signature_method
    assert_equal @request.signature_method,"HMAC-SHA1"  
  end
  
  def test_not_signed
    assert !@request.signed?
  end

  def test_not_verified
    assert !@request.verify?("secret")    
  end

  def test_sign_request_token
    @consumer_secret="kd94hf93k423kf44"
    @test_params={
      :oauth_consumer_key=>"dpf43f3p2l4k3l03"
    }
    
    @request=OAuth::Request.new( :get,'http://photos.example.net/photos?file=vacation.jpg&size=original', @test_params)
    assert !@request.signed?
    assert !@request.verify?(@consumer_secret)
    @request.sign(@consumer_secret)    
    assert @request.signed?
    assert @request.verify?(@consumer_secret)    
    orig_sig=@request.signature
    
    @incoming=mock_incoming_request(@request)
    assert_equal "photos.example.net",@incoming.host_with_port
    assert_equal "/photos",@incoming.path
    assert_equal :get,@incoming.method
    assert_equal( {"file"=>"vacation.jpg",
      "size"=>"original",
      "oauth_consumer_key"=>"dpf43f3p2l4k3l03",
      'oauth_timestamp'=>@request[:oauth_timestamp],
      "oauth_nonce"=>@request[:oauth_nonce],
      "oauth_signature_method"=>'HMAC-SHA1',
      "oauth_version"=>"1.0",
      "oauth_signature"=>orig_sig
      },@incoming.parameters)
    
    @request=OAuth::Request.incoming(@incoming)
    assert @request.signed?
    assert @request.verify?(@consumer_secret)
    assert_equal orig_sig,@request.signature
  end
  
  def mock_incoming_request(request)
    incoming=ActionController::TestRequest.new(@request.to_hash)
    incoming.request_uri=@request.uri.path
    incoming.env["SERVER_PORT"]=@request.uri.port
    incoming.host=@request.uri.host
    incoming.env['REQUEST_METHOD']=@request.http_method
    incoming
  end
  
  def test_sign_access_token
    @consumer_secret="kd94hf93k423kf44"
    @token_secret="pfkkdhi9sl3r4s00"
    @test_params={
      :oauth_consumer_key=>"dpf43f3p2l4k3l03",
      :oauth_token=>"nnch734d00sl2jdk"
    }
    
    @request=OAuth::Request.new( :get,'http://photos.example.net/photos?file=vacation.jpg&size=original', @test_params)
    assert !@request.signed?
    assert !@request.verify?(@consumer_secret,@token_secret)    
    @request.sign(@consumer_secret,@token_secret)    
    assert @request.signed?
    assert @request.verify?(@consumer_secret,@token_secret)    
  end
  
end
