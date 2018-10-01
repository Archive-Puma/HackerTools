#!/usr/bin/env ruby

require 'msf/core'  # Metasploit module

class MetasploitModule < Msf::Auxiliary

  Rank = ExcellentRanking

  include Msf::Exploit::Remote::Tcp

  def initialize
    super(
      'Name'        => 'General Skills: pipe - Points: 110',
      'Description' => %q(
                        During your adventure, you will likely encounter a situation where you need to process data that you receive over the network rather than through a file. Can you find a way to save the output from this program and search for the flag? Connect with 2018shell2.picoctf.com 34532.

                        [HINTS]:
                          Ever heard of a pipe? No not that kind of pipe... and remember the flag format is picoCTF{XXXX}
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
        Opt::RPORT('34532')
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
      flag = ''
      # Collect all data as long as they exist
      loop do
        chunk = sock.get
        break if chunk == ''
        flag = flag + chunk
      end
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
