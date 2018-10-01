#!/usr/bin/env ruby

require 'msf/core'  # Metasploit module

class MetasploitModule < Msf::Auxiliary

  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize
    super(
      'Name'        => 'Web Explotation: Inspect Me - Points: 125',
      'Description' => %q(
                        Inpect this code! http://2018shell2.picoctf.com:53213

                        [HINTS]:
                          How do you inspect a website's code on a browser? Check all the website code.
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
        Opt::RPORT('53213')
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
      # Find the css stylesheet
      file = html_source.scan(/href=.*\.css/)[0]
      file = file.gsub(/href="/, '')

      # Send a GET request to the server
      print_status("Sending GET request to TCP/#{rport} /#{file}...")
      res = send_request_cgi({
        'uri'     => file,
        'method'  => 'GET'
      })
      # Get the body of the request
      css_source = res.get_html_document.to_s

      # Find the first part of the flag in the HTML comments
      html_flag = html_source.scan(/<!--.*-->/)[0]
      html_flag = html_flag.scan(/\bpicoCTF\{\w*/)[0]
      # Find the first part of the flag in the CSS comments
      css_flag = css_source.scan(/\/\*.*\*\//)[0]
      css_flag = css_flag.scan(/\w*\b\}/)[0]
      # Concat the flag
      flag = html_flag + css_flag
      print_good("Solved: #{flag}")
    rescue
      # Handle errors
      print_error('Unhandled exception during execution')
    end
  end

end
