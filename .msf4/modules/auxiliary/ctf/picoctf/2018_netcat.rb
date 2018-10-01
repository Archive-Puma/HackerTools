#!/usr/bin/env ruby

require 'msf/core'  # Metasploit module

class MetasploitModule < Msf::Auxiliary

  Rank = ExcellentRanking

  include Msf::Exploit::Remote::Tcp

  def initialize
    super(
      'Name'        => 'General Skills: net cat - Points: 75',
      'Description' => %q(
                        Using netcat (nc) will be a necessity throughout your adventure. Can you connect to 2018shell2.picoctf.com at port 22847 to get the flag?
                        ),
      'Author'      => ['CosasDePuma <https://github.com/cosasdepuma>'],
      'Privileged'  => 'false',
      'License'     => MSF_LICENSE
    )

    deregister_options(                           # Advanced Options
      'CHOST', 'CPORT', 'SSL', 'SSLCipher',
      'SSLVerifyMode', 'SSLVersion', 'WORKSPACE'
      )

    register_options(
      [
        Opt::RHOST('2018shell2.picoctf.com'),
        Opt::RPORT('22847')
      ], self.class
    )
  end

  def run
    begin
      # Connect to the server
      print_status("Establishing connection...")
      connect
      # Send a request to the server
      print_status("Sending request to TCP/#{rport}")
      flag = sock.get
      # RegExp the flag
      flag = flag.scan(/picoCTF.+/)[0]
      print_good("Solved: #{flag}")
    rescue
      # Handle errors
      print_error('Unhandled exception during execution')
    ensure
      # Ensure to disconnect the server
      disconnect
    end
  end

end
