#!/usr/bin/env python

import sys
import SocketServer
from threading import Thread
import os
import re
fixhead="""<html><head><script type='text/javascript'>
    function fun() {
        var exam=new XMLHttpRequest();
        exam.onreadystatechange=function() {
            if(exam.readyState==4) {
                var obuf='';
				var totalconns=0;
				var totalcps=0;
                var rawrows=exam.responseText.split('\\n');
                rawrows.forEach(function(rawrow){
                    rawcols=rawrow.split(' ');
                    if (rawcols.length>1){
						obuf+='<tr><td>'+rawcols[0]+'</td><td>'+rawcols[1]+'</td><td>'+rawcols[2]+'</td></tr>';
						totalconns+=parseInt(rawcols[1]);
						totalcps+=parseInt(rawcols[2]);
					}else obuf+='<tr><td>'+rawcols[0]+'</td><td></td></tr>';
					});
                document.getElementById('portshowbody').innerHTML=obuf;
				document.getElementById('totalconns').innerHTML=totalconns;
				document.getElementById('totalcps').innerHTML=totalcps;
            }
        }
		exam.open('GET','/"""
fixfoot="""',true);
        exam.send(null);
    }
    setInterval(function(){
        fun();
    },5000);
</script></head><body><table><thead><tr><th>Port</th><th>Connections</th><th>CPS</th></tr><tr><th>Total</th><th id='totalconns'></th><th id='totalcps'></th></tr></thead><tbody id='portshowbody'></tbody></table></body></html>"""
class service(SocketServer.BaseRequestHandler):
    def handle(self):
        data = 'dummy'
        while (data.find("HTTP")==-1):
            data = self.request.recv(1024)

        ln=data.split('\n')[0]
        ln=ln[:-1]
        pattern=re.compile("^GET /d\?s=\d{1,5}&e=\d{1,5} HTTP/1\.1$")
        if pattern.match(ln):
            std,end=ln.split(' ')[1].split('&')
            st=std[std.find('=')+1:]
            en=end[end.find('=')+1:]
            p=os.popen("/root/nf/cli/pkread "+st+" "+en,"r")
            while 1:
                line = p.readline()
                if not line: break
                if(line.find("No Data")!=-1): self.request.send(line.split(" ")[0]+"\n")
                else:
                    d=line.split(" ")
                    self.request.send(d[0]+" "+d[2].split("/")[0]+" "+d[3]+"\n")
        pattern=re.compile("^GET /alld HTTP/1\.1$")
        if pattern.match(ln):
            with open ("/root/nft/.ports", "r") as myfile: portsdata=myfile.read()
            portranges = portsdata.split(' ')
            for portrange in portranges:
                p=os.popen("/root/nf/cli/pkread "+portrange.split('-')[0]+" "+portrange.split('-')[1],"r")
                while 1:
                    line = p.readline()
                    if not line: break
                    if(line.find("No Data")!=-1): self.request.send(line.split(" ")[0]+"\n")
                    else:
                        d=line.split(" ")
                        self.request.send(d[0]+" "+d[2].split("/")[0]+" "+d[3]+"\n")
        pattern=re.compile("^GET /\?s=\d{1,5}&e=\d{1,5} HTTP/1\.1$")
        if pattern.match(ln):
            std,end=ln.split(' ')[1].split('&')
            st=std[std.find('=')+1:]
            en=end[end.find('=')+1:]
            self.request.send(fixhead+"""d?s="""+st+"""&e="""+en+fixfoot)
        pattern=re.compile("^GET /all HTTP/1\.1$")
        if pattern.match(ln):
            self.request.send(fixhead+"""alld"""+fixfoot)
        self.request.close()

class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass

t = ThreadedTCPServer(('',999), service)
try:
    t.serve_forever()
except KeyboardInterrupt:
    sys.exit(1)
