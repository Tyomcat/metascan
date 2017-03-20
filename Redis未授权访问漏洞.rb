require 'socket'

class Metasploit4 < Msf::Auxiliary
  Rank = ExcellentRanking
  include Msf::Auxiliary::Scanner
  def initialize
    super(
      'Name'=> 'Redis Server Unauthorized Access Vulnerability',
      'Version'=> 'All',
      'Description' => %q{Redis未授权访问},
      'Author'=> 'tyomcat',
      'License'=> MSF_LICENSE,
    )
    register_options(
      [
        OptString.new('RHOSTS', [true, 'The Redis Server ip', '']),
        OptString.new('RPORT', [true, 'The Redis Server port', '6379']),
        OptString.new('TIMEOUT', [true, 'Scoket timeout', '1']),
      ], self.class)
  end

  def connect(host, port, timeout)
    addr = Socket.getaddrinfo(host, nil)
    sockaddr = Socket.pack_sockaddr_in(port, addr[0][3])

    Socket.new(Socket.const_get(addr[0][0]), Socket::SOCK_STREAM, 0).tap do |socket|
      socket.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)

      begin
        socket.connect_nonblock(sockaddr)

      rescue IO::WaitWritable
        if IO.select(nil, [socket], nil, timeout)
          begin
            socket.connect_nonblock(sockaddr)
          rescue Errno::EISCONN
          rescue
            socket.close
            raise
          end
        else
          socket.close
          raise "Connection timeout"
        end
      end
    end
  end

  def run_host(ip)
    begin
      connect(ip, "#{datastore['RPORT']}", "#{datastore['TIMEOUT']}".to_i)
      s = TCPSocket.open("#{ip}", "#{datastore['RPORT']}")
      # exec info command
      playload = "\x2a\x31\x0d\x0a\x24\x34\x0d\x0a\x69\x6e\x66\x6f\x0d\x0a"
      s.write("#{playload}")
      # first line unused 
      code = s.gets()
      if /NOAUTH Authentication required/ =~ code
        print_status("#{ip}:#{datastore['RPORT']} need input password")
      else
        # match Server filed message
        if /# Server/ =~ s.gets()
          print_good "#{ip}:#{datastore['RPORT']} is vulnerable"
        end
        s.close
      end
    rescue
      print_status "#{ip}:#{datastore['RPORT']} is closed"
    end
  end
end
