module OAuth
  module Rails
   
    module ControllerMethods
      protected
      
      # use in a before_filter
      def oauth_required
        @token=ClientApplication.authorize_request?(request)
        return false if @token==false
        current_user=@token.user
        true
      end
      
      # This requies that you have an acts_as_authenticated compatible authentication plugin installed
      def login_or_oauth_required
        login_required unless oauth_required
      end
    end
  end
end