require 'spec'
require 'rubygems'
$LOAD_PATH.unshift(File.dirname(__FILE__))
$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), '..', 'lib'))
require 'rack-tamperproof'

def build_builder(config, key = "testing this key", &block)
  app = Rack::Builder.new do
    if key
      use Rack::Tamperproof, :default_key => "testing this key", &config
    else
      use Rack::Tamperproof, &config
    end
    run build_app(& (block || Proc.new{ |a,b|
    }))
  end
  
end

def build_app(&block)
  Proc.new { |env|
    request = Rack::Request.new(env)
    Rack::Response.new do |response|
      response.body = ['hello']
      response.header['Content-type'] = 'text/plain'
      unless request.cookies['test']
        response.set_cookie('test', 'protected') 
      end
      block.call(request, response)
    end.to_a
  }
end

def build_cookie_header(cookies)
  cookies.map{|k,v| "#{Rack::Utils.escape(k)}=#{Rack::Utils.escape(v)}"}.join(';')
end

