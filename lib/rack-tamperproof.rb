require 'rack'
require 'digest/sha1'

module Rack
  class Request
    def delete_cookie(key)
      c = cookies
      c.delete(key)
      env['HTTP_COOKIE'] = c.map{|k,v| "#{Rack::Utils.escape(k)}=#{Rack::Utils.escape(v)}"}.join(';')
      env.delete('rack.request.cookie_string')
      env.delete('rack.request.cookie_hash')
    end
  end
end

module Rack
  class Tamperproof
    
    Tampered = Class.new(RuntimeError)
    
    class Protector
      
      def initialize(name, secret, postfix = '_key')
        @name = name.to_s
        @secret = secret
        @postfix = postfix
      end
      
      def secret_cookie_key
        "#{@name}#{@postfix}"
      end
      
      def self.sign(name, value, secret)
        digest = Digest::SHA1.new
        digest.update(name)
        digest.update(value)
        digest.update(secret)
        digest.hexdigest
      end
      
      def secret(cookies)
        self.class.sign(@name, cookies[@name], @secret)
      end
      
      def valid?(request)
        secret(request.cookies) == request.cookies[secret_cookie_key]
      end
      
      def add_secret_to_response(response, cookies)
        response.set_cookie(secret_cookie_key, secret(cookies))
      end
      
      class ExceptionProtector < Protector
        def validate(request)
          valid?(request) or raise(Tampered.new)
        end
      end

      class DeleteProtector < Protector
        def validate(request)
          unless valid?(request)
            request.delete_cookie(@name)
            request.delete_cookie(secret_cookie_key)
          end
        end
      end
    end
    
    def exception_for(name, key = @default_key || raise)
      @protected_cookies[name.to_s] = Protector::ExceptionProtector.new(name, key)
    end
    
    def delete_for(name, key = @default_key || raise)
      @protected_cookies[name.to_s] = Protector::DeleteProtector.new(name, key)
    end
    
      
    def initialize(app, opts = nil, &block)
      @app = app
      @default_key = opts && opts[:default_key]
      @protected_cookies = {}
      instance_eval(&block)
    end
    
    def call(env)
      
      # detect cookies that are supposed to be tamper proof
      
      request = Rack::Request.new(env)
      request.cookies.each do |name, value|
        if @protected_cookies[name]
          @protected_cookies[name].validate(request)
        end
      end
      
      result = @app.call(env)
      response = Rack::Response.new(result[2], result[0], result[1])
      
      cookies = Rack::Utils.parse_query(response['Set-Cookie'], "\n")
      @protected_cookies.each do |name, protector|
        protector.add_secret_to_response(response, cookies)
      end
      response.to_a
    end
    
  end
end