INVITE sip:UserB@there.com SIP/2.0
Via: SIP/2.0/UDP here.com:5060
From: "BigGuy" <sip:UserA@here.com>
To: "LittleGuy" <sip:UserB@there.com>
Call-ID: 12345601@here.com
CSeq: 1 INVITE
Contact: <sip:UserA@100.101.102.103>
Content-Type: application/sdp
Content-Length: 147

v=0
o=UserA 2890844526 2890844526 IN IP4 here.com
s=Session SDP
c=IN IP4 100.101.102.103
t=0 0
m=audio 49172 RTP/AVP 0
a=rtpmap:0 PCMU/8000
