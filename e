#!/usr/bin/env python

import sys
import SocketServer
from threading import Thread
import os
import re
ms = 2000
fixhead="""<html><head><script type='text/javascript'>
	var lastbytes=0;
    function fun() {

        var exam=new XMLHttpRequest();
        exam.onreadystatechange=function() {
            if(exam.readyState==4){
				if(lastbytes!=0)
					rate = (parseInt(exam.responseText) - lastbytes)/"""+str(ms)+""";
                lastbytes=parseInt(exam.responseText);
                document.getElementById('bps').innerHTML=rate;
            }
        }
		exam.open('GET','/"""
fixfoot="""',true);
        exam.send(null);
    }
    setInterval(function(){
        fun();
    },"""+str(ms)+""");
</script></head><body>Your Download rate[KBps]: <b id='bps'></b></body></html>"""
class service(SocketServer.BaseRequestHandler):
    def handle(self):
        data = 'dummy'
        while (data.find("HTTP")==-1):
            data = self.request.recv(1024)

        ln=data.split('\n')[0]
        ln=ln[:-1]
        pattern=re.compile("^GET /d\?s=\d{1,5} HTTP/1\.1$")
        if pattern.match(ln):
            std=ln.split(' ')[1]
            st=std[std.find('=')+1:]
            p=os.popen("tc -s -d class show dev eth0 classid 1:"+st,"r")
            while 1:
                line = p.readline()
                if not line: break
                if(line.find("Sent")!=-1):
                    d=line.split(" ")
                    self.request.send(d[2])
                    break
        pattern=re.compile("^GET /\?s=\d{1,5} HTTP/1\.1$")
        if pattern.match(ln):
            std=ln.split(' ')[1]
            st=std[std.find('=')+1:]
            self.request.send(fixhead+"""d?s="""+st+fixfoot)
        self.request.close()

class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass

t = ThreadedTCPServer(('',888), service)
try:
    t.serve_forever()
except KeyboardInterrupt:
    sys.exit(1)
