require 'uri'
require 'cgi'
require 'open-uri'
require 'net/http' 
module OAuth
  # It should not normally be necessary to call this directly
  class Request
    include OAuth::Key
    
    attr_accessor :params,:headers
    
    @@default_params={:oauth_signature_method=>'HMAC-SHA1',:oauth_version=>"1.0"}
    
    def initialize(http_method,url,params={},headers={})
      # ensure that keys are strings
      @params=@@default_params.merge( params.inject({}) do |options, (key, value)|
        options[key.to_sym] = value
        options
      end)
      @headers=headers
      self.http_method=http_method
      self.url=url
      self[:oauth_timestamp]=create_timestamp unless self.timestamp
      self[:oauth_nonce]=generate_key(24) unless self.nonce
    end
    
    # This takes a rails like Request and returns an OAuth request object
    def self.incoming(http_request)
      Request.new(http_request.method,"http://#{http_request.host_with_port}#{http_request.path}",http_request.parameters)
    end
    
    def perform(consumer_secret,token_secret=nil,realm=nil,body=nil)
      http_klass=(@uri.scheme=="https" ? Net::HTTPS : Net::HTTP)
      http_klass.start(@uri.host,@uri.port) do |http|
        sign(consumer_secret,token_secret)
        
        # TODO if realm is set use auth header
        if (['POST','PUT'].include?(http_method))
          http.send(http_method.downcase.to_sym,@uri.path,to_query,headers)
        else # any request without a body
          http.send(http_method.downcase.to_sym,"#{@uri.path}?#{to_query}",headers)
        end
      end
    end
    
    def perform_token_request(consumer_secret,token_secret=nil)
      response=perform(consumer_secret,token_secret)
      if response.code=="200"
        CGI.parse(response.body).inject({}){|h,(k,v)| h[k.to_sym]=v.first;h}
      else 
        response.error! 
      end 
    end
    
    def http_method=(value)
      @http_method=value.to_s.strip.upcase
    end
    
    def http_method
      @http_method
    end
    
    def uri
      @uri
    end
    
    def url=(value)
      @uri=URI.parse(value)
      @url=value.downcase
    end
    
    def url
      @url
    end
    
    # produces an array of "key=value"s for the uri_params
    def uri_parameters
      params = uri.query.nil? ? {}: CGI.parse(uri.query).inject({}){|h,(k,v)| h[k]=v[0];h}
    end
    
    def normalized_url
      uri=URI.split(url)
      if uri[3].nil?||(uri[3]=='80'&&uri[0]=='http')||(uri[3]=='443'&&uri[0]=='https')
        port=""
      else
        port=":#{uri[3]}"
      end
      "#{uri[0]}://#{uri[2]}#{port}#{uri[5]}"
    end
    
    def [](key)
      params[key.to_sym]
    end
    
    def []=(key,value)
      params[key.to_sym]=value
    end
    
    def timestamp
      self[:oauth_timestamp]
    end
    
    def create_timestamp
      Time.now.utc.to_i.to_s
    end
    
    def nonce
      self[:oauth_nonce]
    end
    
    def to_name_value_pair_array(hash,with={})
      hash.merge(with).collect{|(key,value)| "#{escape(key.to_s)}=#{escape(value)}"}.sort
    end

    def to_hash(with={})
      params.merge(uri_parameters).merge(with)
    end
    
    def to_query(with={})
      (to_name_value_pair_array(to_hash(with))).sort.join("&")
    end

    def to_query_without_signature(with={})
      (to_name_value_pair_array(params_without_signature,with)).sort.join("&")
    end

    def to_auth_string(with={})
      to_name_value_pair_array(params,with).join(", ")
    end
    
    def to_base_string(secret)
      to_query({:oauth_secret=>secret})
    end

    def params_without_signature
      to_hash.reject{|key,value| key==:oauth_signature}
    end
    
    def signature
      self[:oauth_signature]
    end

    def signature=(_signature)
      self[:oauth_signature]=_signature
    end
    
    def signature_method
      self[:oauth_signature_method]
    end
        
    def signature_method=(_signature_method)
      self[:oauth_signature_method]=_signature_method
    end

    def signed?
      signature!=nil
    end
    
    def sign(consumer_secret,token_secret=nil)
      OAuth::Signature.create(self,consumer_secret,token_secret).sign!
    end
    
    def verify?(consumer_secret,token_secret=nil)
      OAuth::Signature.create(self,consumer_secret,token_secret).verify?
    end
    
  end
end
