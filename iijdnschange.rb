require 'ipaddr'
require 'json'
require 'openssl'
require 'base64'
require 'digest'
require 'net/https'

class IijDnsChange
  @servicecode=nil
  @accesskey=nil
  @secretkey=nil
  @expire=nil
  def initialize(sc,ak,sk)
    @servicecode = sc
    @accesskey = ak
    @secretkey = sk
    set_expiretime
  end

  def put(zone,recordid,owner,record)
    url="/r/20140601/#{@servicecode}/#{zone}/record/#{recordid}.json"
    senddata=JSON.generate({Owner: owner, TTL: "300", RecordType: type(record), RData: record})+"\n"
    md5=md5(senddata)
    sign=sign("PUT",url,md5)
    access("PUT",url,sign,senddata,md5)
  end

  def commit
    url="/r/20140601/#{@servicecode}/commit.json"
    sign=sign("PUT",url)
    access("PUT",url,sign)
  end

  def records(zone)
    url="/r/20140601/#{@servicecode}/#{zone}/records/DETAIL.json"
    sign=sign("GET",url)
    pal=["RData","Id","Owner"]
    type=["CNAME","A"]
    r=access("GET",url,sign)
    r=r["RecordList"].select{|i| type.include?(i["RecordType"])}
    .map{|item| item.select{|k,v| pal.include?(k)}}
    pairing(r)
  end

  def md5(data)
    Digest::MD5.base64digest(data)
  end

  private
  def set_expiretime
    @expire=(Time.now+3600).strftime("%Y-%m-%dT%H:%M:%SZ")
  end

  def access(method,url,sign,senddata="",md5=nil)
    header={'x-iijapi-expire' => @expire,
      'x-iijapi-signaturemethod'=>  "HmacSHA256",
      'x-iijapi-signatureversion' => "2",
      'authorization' => "IIJAPI #{@accesskey}:#{sign}"}
    #https = Net::HTTP.new('www.iij.ad.jp',443)
    https = Net::HTTP.new('do.api.iij.jp',443)
    https.use_ssl = true
    #https.ca_file = File.dirname(__FILE__)+'/globalsign.pem'
    #p File.dirname(__FILE__)+'/globalsign.pem'
    #https.verify_mode = OpenSSL::SSL::VERIFY_PEER
    https.verify_mode = OpenSSL::SSL::VERIFY_NONE
    #https.verify_depth = 5
    if method == "GET" then
      https.start {
        response = https.get(url,header)
        fail "UnexpectedResponseError:#{response.code}" if not response.is_a?(Net::HTTPSuccess)
        s= JSON.parse(response.body) if response.body
      }
    elsif method == "PUT" then
     header['content-md5']=md5 if md5
     header['content-type']="application/json"
     https.start {
     response = https.put(url,senddata,header)
     fail "UnexpectedResponseError:#{response.code}" if not response.is_a?(Net::HTTPSuccess)
     s= JSON.parse(response.body) if response.body
     }
    end
  end

  def type(record)
    begin
      IPAddr.new(record)
    rescue Exception => e
      return "CNAME"
    end
    return "A"
  end

  def pairing(data)
    r={}
    data.each{|item|
      r[item["Owner"]]=item["Id"]
    }
    return r
  end

  def sign(method,url,md5="")
    ctype = method == "PUT" ? "application/json" : ""
text=<<DATA
#{method}
#{md5}
#{ctype}
x-iijapi-expire:#{@expire}
x-iijapi-signaturemethod:HmacSHA256
x-iijapi-signatureversion:2
#{url}
DATA
    return Base64.encode64(OpenSSL::HMAC.digest("SHA256",@secretkey,text.strip)).strip
  end
end

