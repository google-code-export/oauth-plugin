require 'test/unit'
require 'oauth'
class OAuthSignatureTest < Test::Unit::TestCase
  def setup
    # From example in Apendix A of the spec
    @consumer_secret="kd94hf93k423kf44"
    @token_secret="pfkkdhi9sl3r4s00"
    @test_params={
      :oauth_consumer_key=>"dpf43f3p2l4k3l03",
      :oauth_token=>"nnch734d00sl2jdk",
      :oauth_timestamp=>"1191242096",
      :oauth_nonce=>"kllo9940pd9333jh"
    }
    
    @request=OAuth::Request.new( :get,'http://photos.example.net/photos?file=vacation.jpg&size=original', @test_params)
    @signature=OAuth::Signature.create(@request,@consumer_secret,@token_secret)
  end
  
  def test_base_string
    from_spec="GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal&kd94hf93k423kf44&pfkkdhi9sl3r4s00"
    assert_equal from_spec,@signature.base_string
  end
  
  def test_signature_key
    assert_equal "kd94hf93k423kf44&pfkkdhi9sl3r4s00",@signature.key
  end
  
  def test_signature
    assert_equal "Gcg/323lvAsQ707p+y41y14qWfY=",@signature.sign
  end
  
  def test_sign_hmac_sha1
    assert !@request.signed?
    assert !@signature.verify?
    @signature.sign!
    assert @request.signed?
    assert @signature.verify?
  end

  def test_sign_hmac_md5
    @request.signature_method="hmac-md5"
    assert !@request.signed?
    assert !@signature.verify?
    @signature.sign!
    assert @request.signed?
    assert @signature.verify?
  end

  def test_sign_hmac_sha2
    @request.signature_method="hmac-sha2"
    assert !@request.signed?
    assert !@signature.verify?
    @signature.sign!
    assert @request.signed?
    assert @signature.verify?
  end

  def test_sign_hmac_rmd160
    @request.signature_method="hmac-rmd160"
    assert !@request.signed?
    assert !@signature.verify?
    @signature.sign!
    assert @request.signed?
    assert @signature.verify?
  end

  def test_sign_plain
    @request.signature_method="plaintext"
    assert !@request.signed?
    assert !@signature.verify?
    @signature.sign!
    assert @request.signed?
    assert @signature.verify?
  end

  def test_sign_sha1
    @request.signature_method="sha1"
    assert !@request.signed?
    assert !@signature.verify?
    @signature.sign!
    assert @request.signed?
    assert @signature.verify?
  end

  def test_sign_md5
    @request.signature_method="md5"
    assert !@request.signed?
    assert !@signature.verify?
    @signature.sign!
    assert @request.signed?
    assert @signature.verify?
  end

end