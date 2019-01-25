# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals
import requests
import json
import os
import sys
import urllib
reload(sys)
sys.setdefaultencoding('utf8')
from flask import Flask, request, abort, render_template
from wechatpy import parse_message, create_reply
from wechatpy.utils import check_signature
from wechatpy.exceptions import (
    InvalidSignatureException,
    InvalidAppIdException,
)

#send data to iot hardware 
content=""
url="https://api.weixin.qq.com/hardware/mydevice/platform/ctrl_device?access_token=17_FbwKfICMh3UU-XR1RcLkBlg388yhSHeE3yQo2rgak4iUh9R1fNB9sKVVe95kN0Vo1KOSRzUeaudvPOvVRm67Rr7a0_Ouy012BDqwHhiXM23bf-4rA8MD6Gcr2VIGSWfABAYKO"
headers={'content-type':'application/json'}
datajson={ "device_type": "gh_6064295bfad2",
        "device_id":"gh_6064295bfad2_d11fafd815c759ba",
        "user": "oYd-ytwz-EYkcXPb1mo4DmCKaUBw",
        "services": {
        "operation_status": {
            "status": 1
          }
       },
        "data": ""
}

# set token or get from environments
TOKEN = os.getenv('WECHAT_TOKEN', 'brian722')
AES_KEY = os.getenv('WECHAT_AES_KEY', 'a636227739200a71b1ec76be9e5bec81')
APPID = os.getenv('WECHAT_APPID', 'wxc7ffbe44cacb90d0')

app = Flask(__name__)

def fetch_app_access_token(app_id, app_secret):
 resp = urllib.urlopen(
   'https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid='+app_id + '&secret=' + app_secret)
 if resp.getcode() == 200:
   resp_body=resp.read()
   token=json.loads(resp_body.decode('utf-8'))['access_token']
   global url  
   url='https://api.weixin.qq.com/hardware/mydevice/platform/ctrl_device?access_token='+token 
   print('fetch token update '+url) 
   return resp.read()
 else:
   return None


def fixup(adict,k,v):
    for key in adict.keys():
        if key==k:
            adict[key]=v
        elif type(adict[key]) is dict:
             fixup(adict[key],k,v)  
@app.route('/')
def index():
    host = request.url_root
    return render_template('index.html', host=host)


@app.route('/wechat', methods=['GET', 'POST'])
def wechat():
    signature = request.args.get('signature', '')
    timestamp = request.args.get('timestamp', '')
    nonce = request.args.get('nonce', '')
    encrypt_type = request.args.get('encrypt_type', 'raw')
    msg_signature = request.args.get('msg_signature', '')
    try:
        check_signature(TOKEN, signature, timestamp, nonce)
    except InvalidSignatureException:
        abort(403)
    if request.method == 'GET':
        echo_str = request.args.get('echostr', '')
        return echo_str

    # POST request
    if encrypt_type == 'raw':
        # plaintext mode
        print("msg content "+request.data)
        msg = parse_message(request.data)
        if msg.type == 'text':
             print('msg_content:', msg.content )
             datacontent=json.loads(json.dumps(datajson))
             fixup(datacontent,'data',msg.content.decode('unicode_escape'))   
             r=requests.post(url,json.dumps(datacontent))
             print('push to iot device'+r.text)
             if "errmsg" in r.text:    
             	if json.loads(r.text)['errmsg']=='access_token expired' or 'access_token' in json.loads(r.text)['errmsg']:
             		fetch_app_access_token('wxc7ffbe44cacb90d0','a636227739200a71b1ec76be9e5bec81') 
             		r=requests.post(url,json.dumps(datacontent))
            		print('again push to iot device'+r.text+'url:'+url)  
             reply = create_reply(msg.content, msg)
        elif msg.type=='voice':
            print('voice message '+str(msg.media_id)+ 'voice message '+str(msg.format)+'voice recognition '+str(msg.recognition))
            data='{\"msg_type\":voice,\"media_id+\":'+msg.media_id+',\"format\":'+msg.format+'}'
            datacontent=json.loads(json.dumps(datajson))
            fixup(datacontent,'data',data)
            r=requests.post(url,json.dumps(datacontent))
            print('voice to iot device'+r.text)
            if "errmsg" in r.text:    
             	if json.loads(r.text)['errmsg']=='access_token expired':
             		fetch_app_access_token('wxc7ffbe44cacb90d0','a636227739200a71b1ec76be9e5bec81') 
             		r=requests.post(url,json.dumps(datacontent))
            		print('again push to iot device'+r.text+'url:'+url)  
            reply=create_reply('voice message',msg) 
        else:
            reply = create_reply('Sorry, can not handle this for now', msg)
        return reply.render()
    else:
        # encryption mode
        from wechatpy.crypto import WeChatCrypto

        crypto = WeChatCrypto(TOKEN, AES_KEY, APPID)
        try:
            msg = crypto.decrypt_message(
                request.data,
		msg_signature,
                timestamp,
                nonce
            )
        except (InvalidSignatureException, InvalidAppIdException):
            abort(403)
        else:
            msg = parse_message(msg)
            if msg.type == 'text':
                reply = create_reply(msg.content, msg)
            else:
                reply = create_reply('Sorry, can not handle this for now', msg)
            return crypto.encrypt_message(reply.render(), nonce, timestamp)


if __name__ == '__main__':
    app.run('172.105.211.174',80, debug=True)
