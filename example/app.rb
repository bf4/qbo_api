require 'bundler/inline'

=begin
1. Sign up for an intuit quickbooks developer account
2. Go to your app dashboard
  https://developer.intuit.com/v2/ui#/app/dashboard
  Copy the 'Client ID' and the 'Client 'Secret' to your .env
  as QBO_API_CLIENT_ID and QBO_API_CLIENT_SECRET respectively
3. Add a Redirect URI:
  http://localhost:9292/oauth2-redirect
4. Create a new Company (from the manage sandboxes page).
  Don't use it for anything else besides testing this app.
  https://developer.intuit.com/v2/ui#/sandbox
5. Copy the 'Company ID' to your .env as QBO_API_COMPANY_ID
6. Start the example app: rackup example/app.rb
7. Authorize your app
  http://localhost:9292/oauth2

1. Adding a Webhook endpoint URL
  See https://www.twilio.com/blog/2015/09/6-awesome-reasons-to-use-ngrok-when-testing-webhooks.html
  For how to install ngrok and what it is.
  Run: ngrok http 9292 -subdomain=somereasonablyuniquenamehere
  Select all triggers and enter the https url
  https://somereasonablyuniquenamehere/webhooks

  After saving the webhook, clikc 'show token'.
  Add the token to your .env as QBO_API_VERIFIER_TOKEN

  Create a customer the lazy way:
  http://localhost:9292/oauth2/new-customer/testcustomer

  There could be a delay of up to a minute before the webhook fires.

  It'll appear in your logs like:
  {"eventNotifications"=>[{"realmId"=>"XXXX", "dataChangeEvent"=>{"entities"=>[{"name"=>"Customer", "id"=>"62", "operation"=>"Create", "lastUpdated"=>"2018-04-08T04:14:39.000Z"}]}}]}
  Verified: true
  "POST /webhooks HTTP/1.1" 200 - 0.0013
=end

install_gems = true
gemfile(install_gems) do
  source 'https://rubygems.org'
  # This app
  gem 'sinatra'
  gem 'sinatra-contrib'
  # OAuth2 middleware
  gem 'rack-oauth2'
  # OAuth middleware
  # gem 'omniauth'
  # gem 'omniauth-quickbooks'
  # Secrets!
  gem 'dotenv'

  # The gem!
  gem 'qbo_api', path: '.'
end

require 'json'
# Webhook support
require 'openssl'
require 'base64'

Dotenv.load "#{__dir__}/../.env"

class App < Sinatra::Base
  PORT  = ENV.fetch("PORT", 9393)
  # OAuth1 credentials
  CONSUMER_KEY = ENV['QBO_API_CONSUMER_KEY']
  CONSUMER_SECRET = ENV['QBO_API_CONSUMER_SECRET']
  # OAuth2 credentials
  CLIENT_ID = ENV['QBO_API_CLIENT_ID']
  CLIENT_SECRET = ENV['QBO_API_CLIENT_SECRET']
  # OAuth2 authorization endpoints
  REDIRECT_URI = "http://localhost:#{PORT}/oauth2-redirect"
  AUTHORIZATION_ENDPOINT = "https://appcenter.intuit.com/connect/oauth2"
  TOKEN_ENDPOINT = "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer"
  # WebHook verifier token
  VERIFIER_TOKEN = ENV['QBO_API_VERIFIER_TOKEN']

  OAUTH2_CREDS ={
    identifier: CLIENT_ID,
    secret: CLIENT_SECRET,
    redirect_uri: REDIRECT_URI,
    authorization_endpoint: AUTHORIZATION_ENDPOINT,
    token_endpoint: TOKEN_ENDPOINT
  }
  configure do
    $VERBOSE = nil # silence redefined constant warning
    register Sinatra::Reloader
  end

  set :sessions, :true
  set :port, PORT
  # use Rack::Session::Cookie, secret: '34233adasf/qewrq453agqr9(lasfa)'
  # use OmniAuth::Builder do
  #   provider :quickbooks, CONSUMER_KEY, CONSUMER_SECRET
  # end

  helpers do
    def verify_webhook(data, hmac_header)
      digest  = OpenSSL::Digest.new('sha256')
      calculated_hmac = Base64.encode64(OpenSSL::HMAC.digest(digest, VERIFIER_TOKEN, data)).strip
      calculated_hmac == hmac_header
    end

    def oauth2_client
      Rack::OAuth2::Client.new(OAUTH2_CREDS)
    end
  end

  get '/' do
    @app_center = QboApi::APP_CENTER_BASE
    @auth_data = oauth_data
    @port = PORT
    erb :index
  end

  get '/oauth2' do
    session[:state] = SecureRandom.uuid
    @client = oauth2_client
    erb :oauth2
  end

  get '/oauth2-redirect' do
    state = params[:state]
    error = params[:error]
    code = params[:code]
    if state == session[:state]
      client = oauth2_client
      client.authorization_code = code
      if resp = client.access_token!
        session[:refresh_token] = resp.refresh_token
        session[:access_token] = resp.access_token
        session[:realm_id] = params[:realmId]
        erb :oauth2_redirect
      else
        "Something went wrong. Try the process again"
      end
    else
      "Error: #{error}"
    end
  end

  get '/oauth2/customer/:id' do
    if access_token = session[:access_token]
      api = QboApi.new(access_token: access_token, realm_id: session[:realm_id])
      @resp = api.get :customer, params[:id]
    end
    erb :customer
  end

  get '/oauth2/new-customer/:name' do
    if access_token = session[:access_token]
      api = QboApi.new(access_token: access_token, realm_id: session[:realm_id])
      payload = {
        DisplayName: params[:name]
      }
      @resp =
        begin
          api.create :customer, payload: payload
        rescue QboApi::BadRequest => e
          raise unless e.message =~ /6240/
          api.get :customer, ["DisplayName", params[:name]]
        end
      erb :customer
    else
      "No access token"
    end
  end

  post '/webhooks' do
    request.body.rewind
    data = request.body.read
    puts JSON.parse data
    verified = verify_webhook(data, env['HTTP_INTUIT_SIGNATURE'])
    puts "Verified: #{verified}"
  end

  # get '/customer/:id' do
  #   if session[:token]
  #     api = QboApi.new(oauth_data)
  #     @resp = api.get :customer, params[:id]
  #   end
  #   erb :customer
  # end
  #
  # def oauth_data
  #   {
  #     consumer_key: CONSUMER_KEY,
  #     consumer_secret: CONSUMER_SECRET,
  #     token: session[:token],
  #     token_secret: session[:secret],
  #     realm_id: session[:realm_id]
  #   }
  # end

  # get '/auth/quickbooks/callback' do
  #   auth = env["omniauth.auth"][:credentials]
  #   session[:token] = auth[:token]
  #   session[:secret] = auth[:secret]
  #   session[:realm_id] = params['realmId']
  #   '<!DOCTYPE html><html lang="en"><head></head><body><script>window.opener.location.reload(); window.close();</script></body></html>'
  # end
end
