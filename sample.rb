require File.dirname(__FILE__)+'/iijdnschange'
require 'logger'


def logged(mark,process)
  logger = Logger.new('dnschange.log')
  r=nil
  begin
    r=process.call
  rescue
    logger.warn($!.to_s+":"+mark)
    exit 1
  else
    logger.info("Success:"+mark)
  end
  return r
end

puts "Please input '12345678'"
if not defined?(Ocra)
a = gets.strip
exit if not a == '12345678'
else
Digest::MD5.base64digest("")
end
puts "Confirmed"

logger = Logger.new('dnschange.log')
logger.info("start")
iij=IijDnsChange.new("SERVICECODE","ACCESSKEY","SECRETKEY")
dic=logged("records",Proc.new{iij.records("example.com")})
exit if defined?(Ocra)
logged("example.qqq",Proc.new{iij.put("example.com",dic["qqq"],"qqq","192.168.0.1")})
logged("example.ppp",Proc.new{iij.put("example.com",dic["ppp"],"ppp","192.168.0.1")})
logged("commit",Proc.new{iij.commit})
