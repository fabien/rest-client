require 'uri'
require 'net/https'
require 'zlib'
require 'stringio'

require 'curb'

require File.dirname(__FILE__) + '/resource'
require File.dirname(__FILE__) + '/request_errors'

# This module's static methods are the entry point for using the REST client.
#
#   # GET
#   xml = RestClient.get 'http://example.com/resource'
#   jpg = RestClient.get 'http://example.com/resource', :accept => 'image/jpg'
#
#   # authentication and SSL
#   RestClient.get 'https://user:password@example.com/private/resource'
#
#   # POST or PUT with a hash sends parameters as a urlencoded form body
#   RestClient.post 'http://example.com/resource', :param1 => 'one'
#
#   # nest hash parameters
#   RestClient.post 'http://example.com/resource', :nested => { :param1 => 'one' }
#
#   # POST and PUT with raw payloads
#   RestClient.post 'http://example.com/resource', 'the post body', :content_type => 'text/plain'
#   RestClient.post 'http://example.com/resource.xml', xml_doc
#   RestClient.put 'http://example.com/resource.pdf', File.read('my.pdf'), :content_type => 'application/pdf'
#
#   # DELETE
#   RestClient.delete 'http://example.com/resource'
#
# To use with a proxy, just set RestClient.proxy to the proper http proxy:
#
#   RestClient.proxy = "http://proxy.example.com/"
#
# Or inherit the proxy from the environment:
#
#   RestClient.proxy = ENV['http_proxy']
#
# For live tests of RestClient, try using http://rest-test.heroku.com, which echoes back information about the rest call:
#
#   >> RestClient.put 'http://rest-test.heroku.com/resource', :foo => 'baz'
#   => "PUT http://rest-test.heroku.com/resource with a 7 byte payload, content type application/x-www-form-urlencoded {\"foo\"=>\"baz\"}"
#
module RestClient
	
	def self.get(url, headers={})
		Request.execute(:method => :get,
			:url => url,
			:headers => headers)
	end

	def self.post(url, payload, headers={})
		Request.execute(:method => :post,
			:url => url,
			:payload => payload,
			:headers => headers)
	end

	def self.put(url, payload, headers={})
		Request.execute(:method => :put,
			:url => url,
			:payload => payload,
			:headers => headers)
	end

	def self.delete(url, headers={})
		Request.execute(:method => :delete,
			:url => url,
			:headers => headers)
	end

	class <<self
		attr_accessor :proxy
	end

	# Print log of RestClient calls.  Value can be stdout, stderr, or a filename.
	# You can also configure logging by the environment variable RESTCLIENT_LOG.
	def self.log=(log)
		@@log = log
	end

	def self.log    # :nodoc:
		return ENV['RESTCLIENT_LOG'] if ENV['RESTCLIENT_LOG']
		return @@log if defined? @@log
		nil
	end
	
	class Response
	  
	  attr_reader :method, :code, :body
	  
	  def initialize(method)
	    @method = method.to_s.upcase
    end
	  
	  def code=(code)
	    @code = code.to_i
    end
	  
	  def body=(str)
	    @body = decode(str)
    end
	  
	  def size
	    self['content-length'] ? self['content-length'].to_i : self.body.size
    end
	  
	  def [](name)
	    headers[name.downcase]
    end
    
    def headers
      @headers ||= {}
    end
	  
	  def parse_header(str)
	    if (matches = str.match(/^(\S+):(.*)/))
		    headers[matches[1].strip.downcase] = matches[2].strip 
	    end
    end
    
    private
    
    def decode(str)
			if headers['content-encoding'] == 'gzip'
				Zlib::GzipReader.new(StringIO.new(str)).read
			elsif headers['content-encoding'] == 'deflate'
				Zlib::Inflate.new.inflate(str)
			else
				str
			end
		end
	  
  end

	# Internal class used to build and execute the request.
	class Request
		
		attr_reader :method, :url, :payload, :headers, :user, :password
    attr_reader :response

		def self.execute(args)
		  new(args).execute
		end

		def initialize(args)
			@method = args[:method] or raise ArgumentError, "must pass :method"
			@url = args[:url] or raise ArgumentError, "must pass :url"
			@headers = args[:headers] || {}
			@payload = process_payload(args[:payload])
			@user ||= args[:user]
			@password ||= args[:password]
		end

		def execute
		  uri = parse_url_with_auth(url)
		  transmit(uri, make_headers(headers), payload)
		rescue Redirect => e
			@url = e.url
			execute
		end

		def make_headers(user_headers)
			default_headers.merge(user_headers).inject({}) do |final, (key, value)|
				final[key.to_s.gsub(/_/, '-').capitalize] = value.to_s
				final
			end
		end

		def parse_url(url)
			url = "http://#{url}" unless url.match(/^http/)
			URI.parse(url)
		end

		def parse_url_with_auth(url)
			uri = parse_url(url)
			@user     = uri.user     if uri.user
			@password = uri.password if uri.password
			uri.user, uri.password = nil, nil
			uri
		end

		def process_payload(p=nil, parent_key=nil)
			if p.is_a?(Hash)
				@headers[:content_type] ||= 'application/x-www-form-urlencoded'
				p.keys.map do |k|
					key = parent_key ? "#{parent_key}[#{k}]" : k
					if p[k].is_a? Hash
						process_payload(p[k], key)
					else
						value = URI.escape(p[k].to_s, Regexp.new("[^#{URI::PATTERN::UNRESERVED}]"))
						"#{key}=#{value}"
					end
				end.join("&")
		  else
		    p
			end
		end
		
		def transmit(uri, headers, payload)
		  @response = Response.new(method)
		  
		  display_log(request_log(uri, headers, payload))
		  
      curl = Curl::Easy.new(uri.to_s)
      curl.on_header { |header_data| response.parse_header(header_data) }
      
      curl.headers = headers
      curl.userpwd = "#{user}:#{password}" if user
      
      curl.follow_location = true
      curl.max_redirects   = 5
      curl.enable_cookies  = true
        
      if RestClient.proxy
				proxy_uri = URI.parse(RestClient.proxy)
				curl.proxypwd   = "#{proxy_uri.user}:#{proxy_uri.password}"
				curl.proxy_url  = proxy_uri.host
				curl.proxy_port = proxy_uri.port
      end
      
      begin
  		  case(method)
  	    when :get     then curl.http_get
  	    when :post    then curl.http_post(payload || '')
  	    when :put     then curl.http_put(payload  || '')
  	    when :delete  then curl.http_delete
        when :head    then curl.http_head
  	    end
	    rescue Curl::Err::GotNothingError
      end
	    
	    response.code = curl.response_code
	    response.body = curl.body_str
	    
	    display_log response_log(response)
	    
	    process_result(response)
		rescue Curl::Err::ReadError, Curl::Err::HTTPFailedError, Curl::Err::RecvError
			raise RestClient::ServerBrokeConnection
		rescue Curl::Err::TimeoutError
			raise RestClient::RequestTimeout
		end

		def process_result(res)
			if [200, 201, 202].include?(res.code)
        res.body
      elsif [301, 302, 303].include?(res.code) && (url = res['location'])
        if url !~ /^http/
          uri = URI.parse(@url)
          uri.path = "/#{url}".squeeze('/')
          url = uri.to_s
        end
        raise Redirect, url
      elsif res.code == 401
        raise Unauthorized, res
      elsif res.code == 404
        raise ResourceNotFound, res
      else
        raise RequestFailed, res
      end
		end

		def request_log(uri, headers, payload)
			out = []
			out << "RestClient.#{method} #{uri}"
			out << (payload.size > 100 ? "(#{payload.size} byte payload)".inspect : payload.inspect) if payload
			out << headers.inspect.gsub(/^\{/, '').gsub(/\}$/, '') unless headers.empty?
			out.join(', ')
		end

		def response_log(res)
			"# => #{res.code} #{res.method} | #{(res['content-type'] || '').gsub(/;.*$/, '')} #{res.size} bytes"
		end

		def display_log(msg)
			return unless log_to = RestClient.log
			if log_to == 'stdout'
				STDOUT.puts msg
			elsif log_to == 'stderr'
				STDERR.puts msg
			else
				File.open(log_to, 'a') { |f| f.puts msg }
			end
		end

		def default_headers
			{ :accept => 'application/xml', :accept_encoding => 'gzip, deflate' }
		end
		
	end
end
