#!/usr/bin/env ruby

require 'msf/core'  # Metasploit module

class MetasploitModule < Msf::Auxiliary

  Rank = ExcellentRanking

  require 'json'      # JSON Module
  require 'base64'    # Base64 Module
  require 'net/https' # HTTPS Module

  def initialize
    super(
      'Name'        => 'HackTheBox Invite API',
      'Description' => 'Invite Code Generator to join HackTheBox.eu',
      'Author'      => ['CosasDePuma <https://github.com/cosasdepuma>'],
      'Privileged'  => 'false',
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        OptString.new('URI', ['true', 'HackTheBox Invite Code API URL', 'https://www.hackthebox.eu/api/invite/generate'])
      ], self.class
    )
  end

  def run
    # Parse the URI
    uri = URI.parse(datastore['URI'])
    # Create the HTTPS object
    https = Net::HTTP.new(uri.host, uri.port)
    https.use_ssl = true
    # Create the POST request
    req = Net::HTTP::Post.new(uri.path)
    print_status('Sending POST request...')
    # Get the response
    begin
      res = https.request(req)
      res = JSON.parse(res.body)
      # Checking the code
      if res['success'] == 1
        # Showing the Invite Code
        print_good('Invite Code obtained: ' + Base64.decode64(res['data']['code']))
      else
        print_error('Error trying to get the Invite Code')
      end
    # Check if the POST was not successfull
    rescue
      print_error('Can\'t open the URI')
    end
  end

end