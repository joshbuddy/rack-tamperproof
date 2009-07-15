require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

describe "Rack-Tamperproof" do

  describe "key signing" do
    it "should use all three values to create a key" do
      vals = ['value0','value1','value2']
      3.times do |i|
        Rack::Tamperproof::Protector.sign(*vals).should_not == Rack::Tamperproof::Protector.sign(*vals.map{|v| v[-1] == i.to_s[0] ? v.upcase : v})
      end
    end
  end

  describe "with a delete cookie" do

    it "should generate a secret" do
      response = build_builder(Proc.new{
        delete_for :test
      }).call(Rack::MockRequest.env_for('/'))
      headers = Rack::Utils::HeaderHash.new(response[1])
      cookies = Rack::Utils.parse_query(headers['Set-Cookie'], "\n")
      cookies['test'].should == 'protected'
      cookies['test_key'].should == Rack::Tamperproof::Protector.sign('test', 'protected', 'testing this key')
    end

    it "should delete a tampered cookie" do
      response = build_builder(Proc.new{
        delete_for :test
      }) { |request, response|
        request.cookies['test'].should == nil
      }.call(Rack::MockRequest.env_for('/', {
        'HTTP_COOKIE' => build_cookie_header({'test' => 'protected2', 'test_key' => Rack::Tamperproof::Protector.sign('test', 'protected', 'testing this key')})
      }))
      
    end

    it "should allow override of the secret" do
      response = build_builder(Proc.new{
        delete_for :test, 'my new secret'
      }).call(Rack::MockRequest.env_for('/'))
      headers = Rack::Utils::HeaderHash.new(response[1])
      cookies = Rack::Utils.parse_query(headers['Set-Cookie'], "\n")
      cookies['test'].should == 'protected'
      cookies['test_key'].should == Rack::Tamperproof::Protector.sign('test', 'protected', 'my new secret')
    end

    it "should raise if no default is given" do
      Proc.new {
        build_builder(Proc.new{
          delete_for :test
        }, nil) { |request, response|
          request.cookies['test'].should == nil
        }.call(Rack::MockRequest.env_for('/', {
          'HTTP_COOKIE' => build_cookie_header({'test' => 'protected2', 'test_key' => Rack::Tamperproof::Protector.sign('test', 'protected', 'testing this key')})
        }))
      }.should raise_error
    end
  end

  describe "with an exception cookie" do
    it "should generate a secret" do
      response = build_builder(Proc.new{
        exception_for :test
      }).call(Rack::MockRequest.env_for('/'))
      headers = Rack::Utils::HeaderHash.new(response[1])
      cookies = Rack::Utils.parse_query(headers['Set-Cookie'], "\n")
      cookies['test'].should == 'protected'
      cookies['test_key'].should == Rack::Tamperproof::Protector.sign('test', 'protected', 'testing this key')
    end

    it "should raise an exception on a tampered cookie" do
      Proc.new {build_builder(Proc.new{
        exception_for :test
      }).call(Rack::MockRequest.env_for('/', {
        'HTTP_COOKIE' => build_cookie_header({'test' => 'protected2', 'test_key' => Rack::Tamperproof::Protector.sign('test', 'protected', 'testing this key')})
      }))}.should raise_error

    end

    it "should allow override of the secret" do
      response = build_builder(Proc.new{
        exception_for :test, 'my new secret'
      }).call(Rack::MockRequest.env_for('/'))
      headers = Rack::Utils::HeaderHash.new(response[1])
      cookies = Rack::Utils.parse_query(headers['Set-Cookie'], "\n")
      cookies['test'].should == 'protected'
      cookies['test_key'].should == Rack::Tamperproof::Protector.sign('test', 'protected', 'my new secret')
    end


  end

end
