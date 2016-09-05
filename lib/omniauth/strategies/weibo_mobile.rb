require "omniauth-oauth2"

module OmniAuth
  module Strategies
    class WeiboMobile < OmniAuth::Strategies::OAuth2
      # Give your strategy a name
      option :name, 'weibo_mobile'

      option :client_options, {
        :site           => "https://api.weibo.com",
        :authorize_url  => "/oauth2/authorize",
        :token_url      => "/oauth2/access_token",
        :token_method => :post
      }

      option :access_token_options, {
        :header_format => 'OAuth %s',
        :param_name => 'access_token'
      }

      attr_accessor :access_token

      uid do
        raw_info['id']
      end

      info do
        {
          :nickname     => raw_info['screen_name'],
          :name         => raw_info['name'],
          :location     => raw_info['location'],
          :image        => raw_info['avatar_hd'],
          :description  => raw_info['description'],
          :urls => {
            'Blog'      => raw_info['url'],
            'Weibo'     => raw_info['domain'].present?? "http://weibo.com/#{raw_info['domain']}" : "http://weibo.com/u/#{raw_info['id']}",
          }
        }
      end

      extra do
        {
          :raw_info => raw_info
        }
      end

      credentials do
        hash = {'token' => access_token.token}
        hash.merge!('refresh_token' => access_token.refresh_token) if access_token.expires? && access_token.refresh_token
        hash.merge!('expires_at' => access_token.expires_at) if access_token.expires?
        hash.merge!('expires' => access_token.expires?)
        hash
      end

      def raw_info
        access_token.options[:mode] = :query
        access_token.options[:param_name] = 'access_token'
        @uid ||= access_token.get('/2/account/get_uid.json').parsed["uid"]
        @raw_info ||= access_token.get("/2/users/show.json", :params => {:uid => @uid}).parsed
      end

      ##
      # You can pass +display+, +with_offical_account+ or +state+ params to the auth request, if
      # you need to set them dynamically. You can also set these options
      # in the OmniAuth config :authorize_params option.
      #
      # /auth/weibo?display=mobile&with_offical_account=1
      #
      def authorize_params
        super.tap do |params|
          %w[display with_offical_account forcelogin].each do |v|
            if request.params[v]
              params[v.to_sym] = request.params[v]
            end
          end
        end
      end

      def callback_phase
        if !request.params['access_token'] || request.params['access_token'].to_s.empty?
          raise ArgumentError.new("No access token provided.")
        end

        self.access_token = build_access_token
        self.access_token = self.access_token.refresh! if self.access_token.expired?

        # Instead of calling super, duplicate the functionlity, but change the provider to 'weibo'.
        # This is done in order to preserve compatibilty with the regular weibo provider
        hash = auth_hash
        hash[:provider] = "weibo_mobile"
        self.env['omniauth.auth'] = hash
        call_app!

       rescue ::OAuth2::Error => e
         fail!(:invalid_credentials, e)
       rescue ::MultiJson::DecodeError => e
         fail!(:invalid_response, e)
       rescue ::Timeout::Error, ::Errno::ETIMEDOUT => e
         fail!(:timeout, e)
       rescue ::SocketError => e
         fail!(:failed_to_connect, e)
      end

      protected

      def build_access_token
        # Options supported by `::OAuth2::AccessToken#initialize` and not overridden by `access_token_options`
        hash = request.params.slice("access_token", "expires_at", "refresh_token", "uid")
        hash.update(options.access_token_options)
        ::OAuth2::AccessToken.from_hash(
          client,
          hash
        )
      end

    end
  end
end
