#!/usr/bin/env python3

import argparse
import socket
import sys
import traceback

"""Test Case Write-up:

Behavior:
    This test case generates a image response. 
Tests:
    This server tests whether the client can correctly handle image data sent by server.

Notes:
    You should copy and modify this test-case to create your own new test cases.
"""


def get_test_response():
    """Create the test response.

    Args:
        None

    Returns:
        The created response (str)
    """
    response_body = b"""\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00\xff\xdb\x00C\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\t\t\x08\n\x0c\x14\r\x0c\x0b\x0b\x0c\x19\x12\x13\x0f\x14\x1d\x1a\x1f\x1e\x1d\x1a\x1c\x1c $.\' ",#\x1c\x1c(7),01444\x1f\'9=82<.342\xff\xdb\x00C\x01\t\t\t\x0c\x0b\x0c\x18\r\r\x182!\x1c!22222222222222222222222222222222222222222222222222\xff\xc0\x00\x11\x08\x00\xa0\x00\xa0\x03\x01"\x00\x02\x11\x01\x03\x11\x01\xff\xc4\x00\x1c\x00\x00\x01\x05\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x01\x02\x03\x05\x06\x07\x00\x08\xff\xc4\x00P\x10\x00\x01\x03\x02\x03\x03\x06\x07\n\x08\x0e\x03\x01\x00\x00\x00\x01\x02\x03\x04\x00\x11\x05\x12!\x061A\x13"Qa\xd1\xd2\x07\x14\x15q\x81\x91\x9423BSU\x92\x93\xa1\xb1\xc1\x1645ERbt\xe1#$CDTcrs\x82\x83\x84\xa2\xf0\xf1\x17%\xb2\xe2\xff\xc4\x00\x19\x01\x00\x02\x03\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05\xff\xc4\x00$\x11\x00\x02\x01\x04\x02\x03\x00\x02\x03\x00\x00\x00\x00\x00\x00\x00\x00\x01\x02\x03\x11\x12!\x041\x13AQ2qa\x91\xb1\xff\xda\x00\x0c\x03\x01\x00\x02\x11\x03\x11\x00?\x00\xe2\xb7\x1d"\xa3#\x8d\xa9\xe47}\xe2\x90\xa5\x04h\xa1\xe9\xa9\x88\xee;12\x08\xd9\x0c\x1c=\x16R\x9d\x11\x10\x14\xa4\xb2\x086\xeb\xbfEX*v\x16\x91\x7f\x11\x9b\xaf\xf5\t\xefP\x1b-\x8aIwdp\x820\xc6\x9c\xcb\x15-\x95\x97H\xbe[\xa7v]7U\x9a\xb1\t\'\xf33^\xd0{\xb5\xc8\x9f\xe4\xcb\xd7D#\x10\xc2\xc1\xd2\x14\xe1\xe6a=\xea\x7f\x94p\xdb\xfe%:\xff\x00\xdc\xa7\xbdHq\t\x00\xfeFk\xda\x0fv\xbd\xe5\t?#\xb7\xed\x07\xbbQ\x19\xef(\xe1\xc4\xe9\x0eo\xd0\xa7\xbdI\xe5\x1c;\x7f\x88\xce\xbf\xf7H\xefR\xf9B@\xfc\xcc\xd7\xd3\x9e\xed\'\x94$\xdf\xf2;_N{\xb4\x08\xf3\xd3`ee~%/z\x80\x1c\x9an7^\xfc\xea\xf0\xc4 q\x857\xd0\x84w\xaa7\xa7>9\x15\x1c-\xbb\xa8\x91\x97\x966\x1c\x7fG\xcfR\'\x12\x96\x13\xa6\x0e\xc7\xa6B\xbb\xb4\x0cx\xc4 \xdfH\x13~b;\xd5\'\x94\xa1q\x814\x8f\xec\xa3\xbdP\xf9JU\xff\x00#1o\xda\x15\xdd\xa7\'\x12\x94\x7f41\xed\n\xee\xd0"O(\xc3\xd7\xff\x00]4\xfa\x11\xde\xaf\x1cF \xfc\xdb;\xd4\x8e\xf5{\xca2\xc7\xe6\x86=\xa1]\xda\xf7\x94\xa6\xfc\x8f\x1f\xda\x15\xdd\xa0\x04\xf2\x94_\x93g\x7f\xb3\xbdI\xe5(\x7f&\xcd\xbf\xf8;i|\xa57\xe4x\xdb\xbe=]\xdai\xc4f\xdfL"7\xd3+\xb2\x80\x13\xcaQ\x07\xe6\xb9\x9e\xb4v\xd3N\'\x16\xff\x00\x92\xa6|\xe4v\xd2\xf9Fo\xc9\x11\xbe\x99]\x94\xd3\x88N\xf9&/\xd2\xab\xb2\x90\xc5\x18\xa3\'v\x11/\xd2\xb4v\xd2\xf9U\xaf\x92%\xfc\xf4RyG\x10\xe1\x85E\xfaUvR\xf9C\x10\xf92/\xd2+\xb2\x81\x1f?Xo\xc9\xeb\xa6\x90\x7fDz)@\n^Qu,\xeb\x94ji\x14\x9c\xaa\xcaAJ\xba\x15\xa1\xfa\xeb\xb4Puo\x06k\xc6F\xcc<#\xba\xd8\x8c%\xac6\x97\x1a\x0b\xcar\xa75\xaf\xbbS\xbb\xcf["\xe6<w=\x1b\xd3\x18W+\xf0\x7f\x8b\xc8o\x12\xf2*\xa5\xbe\xc32\n\x9cmh|\xb6\x94\xac&\xe6\xfa\x81b\x13\xeb\x15\xd2\xc4\x19\n\xb5\xb1\xd7\x88\xfd\xb8\xf7\xab\x99^-M\x97E\xe8\x95g\x1d\xf8\xd8\xc7\xfd0\xa6\x85\xe3\xd7\xf7\xd8\xd6\xfd\x98v\xd3<BV\xff\x00.\xbd\xed\xa7\xbdQ\xf9:]\xff\x00.=\xed\x9f\xfe\xaa\x91\x84\x171\xc0l]\x8b{_\xf1a\xdbI\x9f\x1e\xf8\xc8\xbe\xcc*\x87\x1f\x99/\x01~\x1d\xe7Kt:\x0f(\xb1 \xdf/\x00\r\xfc\xfe\xba\xb4\x8e\xc4\x99q\xd1!\x9cn_$\xb1\xa12l|\xdb\xea\xc9Sq\x8a\x97\xd1&\x993\xcb\xc6\x00j\xea\x8e\\\x04\xdc\x98\xc2\xc3\xa3O]=+\xc6\xc8\xf7\xd8\xde\xcc*\x07a\xcd\x01\xb4\x8cU\xf2G\xbaQ\x95bA=7\xd6\xd4\xa2\x0c\xcd\xc3\x1a\x92\x0f\xed_\xbe\xab$O\x9f\x1c\xf8\xc8\xde\xcc+\xc1\xccv\xfe\xf9\x1b\xd9\x87mE\xe4\xf9\xa7v3(\xf9\xa5~\xfa\xf7\x93\xa7\xfc\xb1+\xda\x7f}\x00\x12\x17\x8e[\xdf#{8\xed\xa5\x0b\xc7~67\xb3\x0e\xda\x898v \xad\xd8\xbc\xb3\xe6\x91zp\xc31\x0f\x95\xa5\x9f\xf3\xe8\x10\xe2\xe68?\x95\x8d\xec\xc2\xbd\xcac\x96\xf7\xc8\xde\xcc)<\x99\x88\x82m\x8a\xcc\xfazC\x86b\x97\xfc\xab/\xe9\xe8\x03\xc5\xccs\xe3#\x1f\xf4\xc2\x93\x94\xc7>2?\xb3\x0e\xdaC\x86\xe2g\xf3\xac\xc3\xd5\xcb\x1aC\x85\xe2\xb7\xfc\xa93\xe9h\x01\xd9\xf1\xdb{\xec\x7fg\x15\xe0q\xcbh\xec\x7fg\x14\xdf%\xe2\x9b\xbc\xa97\xe9\xa9\x0e\x19\x8a|\xa97\xe9M\x036\xf8N\x0b\x86`0\x93\x17\n\x82\xc46\x92\x00\xbbi\xe7+\xadJ\xde\xa3\xd6M\x01\x8e\xe1\xf118\xabf|fe6o\xcdy\x01^\xab\xea=\x15~@\xaa\xc9\xe0e7\xdf]\x19\x11H\xe1ol\xcc\x1d\x9f\xdb\x98*u\xd5#\x0bw\x94R3$\xac\xa5A\'\x99\xd2F\xb7\x06\xb5\t;1\xc5\xc5\x0f<UvT\xdbL\xe4x\x92c\xcf\x95\x15R\x99\x86\xf8}L\xa7\xdd8\x00 \x81~\xa3U\xc9\xf0\x8f\xb2\x83C\xb1\xd8\x8f\xcfI\xfb\xab<\xe3*\x8e\xe3iD;.\xcc\x11\xef\x87\xd9U\xd9I\x97f/\x97\x96\xb1\xbd\x85\xe3\xa8k\xea\xa1\xc7\x84\x8d\x92$_dq4\x81\xfa\xc9\xa9Z\xdb\xed\x8f\x92\xe2[\xfc\x17\xc4\xee\xb3\x94\x12S\xbf\x80\xdf\xa5G\xc1 \xc9\x12m\x96\x1c\xc3\xd8L\'c*\xe9\x08\xe4\xc1\xb1\xd3\xa0\xeb\xadd\xf0I\xac\xa5\xf45-\x01M\xde\xca\x04\\\x83\xba\xb7\xdbA1\x8cK\x04f;P\x1d\x8c\x97[\xce\x80\xf2\x82T\x82\r\xac@\xac\x1bXrS(\xb8\xf2/su\x13r+r\x85\xe0\xa2\xca2\xdd\xcdD\x96pD\xba\xa4:\xf0@l\x80\x80YQ\x04Z\xe4\xdc\x0e\x92}T\xd0\x8d\x9d\xb1\xfe2\xd8\xb7\xf5\x0b\xee\xd41\xe60\xca\x03R\\J\xda\xdd\x90\xa2\xe2\xde}\xe3\xd1W\x86n\xcb\xb5\x1f\x94s\n\x96\xea\x80\xb9K\x0b\x07\xd4\x14\xa1Yg\xc5\x92\xfcK\x15D\xfb*C{8N\xb2\x9a\xbf\xf7+\xee\xd7\xb9-\x9b\xbf\xe3\x8d}\x12\xbb\xb4\xc76\xdb\xc1\xfb+({\n\xc6\xdbP\xde\x14\xd2{\xf4\x9f\x87^\x0e8\xc3\xc6\x07\xf9I\xef\xd5^\t\x93\xc9\x12\xa5\xad\x9b\xbe\x93\x1a\xbfG$\xbe\xca\x97\x91\xd9\xbf\xe9\xb1\xf4\xfdC\xd9P\'m\xbc\x1b\xab\xf9\xae1a\xc7\x90\x1d\xfap\xdb\x7f\x06cz1Q\xd3x\xe3\xbdG\x82a\x92$\x0c\xec\xe5\xed\xe3\xb1\xfej\x87\xddJ"\xec\xee\xe1>5\xba,{)\x9f\x86\xbe\x0c\x8f\xc3\xc4\xc0\xeb\x8e;\xd4\xbf\x86^\x0c\x945{\x12OW\x8a\xf6\x1a<\x13\x16Hw\x8a\xec\xe8\xfe\x7f\x17\xe6\x9e\xcaa\x8f\xb3\xc3t\xe8\xbf_e8mo\x82\xee21\x1fg=\xb5(\xda\xbf\x05V\xbf\x8e\xe2\x1e\xce\xaa<\x13\x1eH\x1f\xc5\xb6z\xff\x00\x8f\xc6\xfa\xfb+\xde/\xb3\xdf(E\xf5\xfe\xea\'\xf0\x9f\xc1R\xb7O\x9e<\xf1\x96~\xeaO\xc2?\x05\xe5:b\x93\x07Y\x8a\xbe\xca<\x13\x0c\x91\xd5Tl*\xaf\x107l\xeaEY-B\xd5]0]&\xd5\xae@\x8c\x06\xd1\';K\x07u\xab\x1c\xdb\xd0-\xabR\t\xeaRku\xb4H\xb3\x0ey\x8dr\xf4\xcee&\xc7?\xcc&\xb3\xb4\xd9m\xcb\xaeW\x0f\xf8\xa9#\xfcB\xb4\xdb5\x87Fv[jC\xa8.\xfb\xa4\xb2\xea\xac\xa5\x00/a\xc0\x9e\xaa\xc1\xb7=\x87\x1dB\x12\xa5fQ\xb0\x05\xb5vWP\x9e\xcc\x98\x98\x0c5\xc6\x84\xdb\x8d\xa9L\xa7\x97\'\xdcku\x1b\xef\n\x1f}YJ-;\xb4UVZ\xb1K>Yy\xb2\xf6B\xe3\xabQ\x08\xfdPw\xd5aw\x93l\x97\x17\x9e\xd7\xb9;\xaa\xc7\x10[\xa8uHKJqn\x9b6\x84\x8b\x92I\xdc*I[#\x8bbO\xb2\xda\x99DVR\xdeu4T3\xee\xdd\x97}m3\x14M\xcd\x8b\xc9\x87\xb9;\xa8X |\x12MWM\xdaGc\xc8\xc8\x86\x91}5UI\'\'\x8d\x96\x90\x87\x13\x92\xe9AZm~\xaa\xa6\x92\xdbrJXsB\r\xb3\x91\xa84\x9b\x1a4+\xda\x882\x18\x06d,\xca\xb6\xaa\xe57\x1e\xae4$6\xa5\xe2\xef-Pb\xa9\xa6RE\xd6\xe9\xbePzhl\x0b\x03mx\xba\x18\x96\xe7&\xa4s\xaeE\xc2\xd3\xd2:Et\xacI\xc8xN\x12\x1ak*\x10\xa4\x1c\xc4\'\x9b~\x06\xe3u\xfazj\x0e*]\x92\xca\xdd\x1c\xd5A\xc4b)i\xe7\xc9\x04\xd9G.\xefE\x1cY\xc3\xc0\xb1\x99\xe8\xf1b~\xfa\xafyM5!n8\xf0&\xf7\nU\x81\xb1\xddL3#\xab^Y\xbf\x9dYj-\xe8\xbe\x0f[-9\x0c;\x7f\x8f\x01\xe7\x8a\xaaO\x15\xc3\x88\xfc}\x1e\xc8\xba\xae\x12Y&\xc1\xd6\xfex\xa5\x0f4u\xe5Q\xf4\x82\xa1fOE\x80\x8b\x87\x13a=\xae\x8etE\xf6W\xbcG\x0f\xfe\x9f\x1f\xd9W\xdd\xa0\x03\xcd\x91\xa3\xa9?\xe3\x14\xa1\xc4\xde\xdc\xa2}\x04R\xb0\x07\xf8\x96\x1cH\xfe=\x17\xd3\x15}\xdaa\xc3p\xf3\xfc\xf2\t\x1dq\x97\xdc\xa1B\xd1\xbf:~p\xa4\xe5\x10~\x12}tlg\xd1\x8b7\xddB\xbe9\xa6\x88\xb5\xc5\xe8i\x17\xb1\xd2\xb4\xb2\xa4d6\x88\x0eEzp5\x9b\x88\xd3\x1e.\x93\xc9\xb7\xeewe\xad.\xd0\x83\xe2\xce\xdf\x805\x99\xc3}\xe5\x04\x8b\x8b\x0e5\x9e}\x96\x16\x90\xf0\x9f*\xc8\r2\xca\t<\xfb\x04\x81}:j\x19{C\x12+&:\x92A\x06\xc5\'\x81\x1aV\x83\x00\xc4\xd8\x81#:\x80\x03(\xb9\t\xa1\xf0\x9d\x94\xd9\xbcU\xa98\xb3\xf1\x9e~Iy\xd5\x04\xb8\xb2\x05\xb3\x13kV\xaa:\x8e\x8c\xf56\xcc{\xb8\xfc\xf6e"Dv\x02\x16\xd79\xb5-4\xdcF\x14\xec c\x18\xce\xd0\xb0\xe4\xccY\xe6P\xee\x1e\xe0t\x84\x84*\xda\xa0\x8f\xd1\xe2(\xecBH\x92\xea\xd9DC\x91\x9e\t\xf7I\x1d`\xebB\xc7\xda\xc9P\x98T@\xf9q\x94\\%\x97\x80q\x1e\x80oVJ7Ei\x86\xe31\n\xd5\xcax\x9a\x9fg\x92\x0f-\xc4\x93\x99\xb5iq~?ma\xa7\x92\xeb\xeb-\\\xe67\xb95\x7f?m\xe7Hd\xb2\xa2\x94\xb4\x7f\x93BBG\xa6\xd5\x96q\xf2\xb9E\xd3\xcd+<\x06\x94$\xd2\xb3w\x19\xa1\xc36\x85q\xb0\xf5\xb0\xfb)Z\x9aI[JY\xd5="\xf7\xb9\xbdV\xcd\xda\xf1)\xa7AK\xc9qH(W>\xc1W\x16\xb9\x03K\x8e\x9d/\xc6\x81R\x0b\xb7I6\xbf\x1a\x0c\xc7CJ\xe7\x01n\x9a\x1b\x02|.IPw2\x10\xe5\xed\xa2\xc6o\xb6\xadbJ\x84V\x94\xc8\x82\xc9H:\x9c\xba\xd6~\x14\x94\xb2\xf2\x85\xb9\xa4\xebG\xf2\x8d\xa8\xdc\x1d\rW\x82d\xf2h\xd47\x1b\x02p!)j1Z\x8d\xect\xa2\x11\x83a\xa4\x1bDj\xc0\xf4V=jI\x19t$q\xa2!\xe2\xef\xc5VP\xb5\x11\xd0u\x06\xaa\x95\'\xe9\x93U>\x9a\xe1\x81ad\xeb\x11\xa0,=\xc8\xeb\xa6y\x07\r\xb0\xbcD\x10x\xda\x9b\x03\x16bU\x809N\x97\x07x\x15f\xa5\xfc N\xeb\xee\x15K\xc9i\x96\xab>\x8a\xb3\xb3\xf8]\xaea\xb7\xa6\xfd+\xc9\xd9\xcc \xa6\xea\x84\x80o}\xdb\xe8\xf5)9\x95\xce\xb1\xb8\xd3\x8e\xearW`\x91{k\xae\x9b\xe9]\x85\x91\xd7\xc3|\xda\x15\xe0\x9b\x94\xd1\xa5V\x14\x04\x8b\x973$V\xb2\xb3/\xb4-\x1eIb\xdb\xc1\xac\\5r`6M\xb4\xb7Ut<L\xa9g\x9e\xc6d\xda\xc4t\xd7?\x99\x18\xc4\x9c\xa4\xb4\xd3\xaad\x9c\xc9\xcc\x82l:\xea\x89\xa2\xc0\xb6\x96R\x81\xcf\x04\x1e\x06\x8dV4\xe6\x03\x01\xc9%9\x9auYr\x93\xa1?\xf5T\xf1\xd7\x9bp$Z\xdc\xdf8\xa2\xf1\x18\x12$Af\\7\x92\xa4\xb5t\xbd\x15v\xca\xbe!Z\xee4QM\xc8\x8c\xb1_\x97@\xf8\x8e=\x16<\xc6\xdcZ\x1ag3\x88\n\xcen\x13\x98s\x14\xae)\x06\xc4\\n\xaaiX_\x8d\xbe\xeb\xe1\xa7\x12\xa4\xac\xa5\xe6\xd2\x05\xda_\xde8\x827\xde\x84\xfc\x1d\xc4q,jt\x99\x8d\xb2\xcb\x12\xb4ZB\xf9\xa2\xfa\xa4_\x85\x88\x06\xb5Qg\xe1\x98F\x12\x96\x10\xf2W1\x96\x82H\xe2\xe2\x13\xae^\xbbp\xea\xd2\xb7~\xcc\xae\xde\x8c<\xdc2K.\x97\x18\xca\xf2\x00\xcc\xa4_\x9c\x07M\xb8\x8e\xb1z\x89\x08i\xd4\x02\xa5\x04\x1e\xba\xb5\x9d\x8d\xb3\x89\x92\xaeD\x02\x92NT+\x9e\x9f\xd6I\xe9\xfbw\x1e\x9a\xa3\x96\xdbo\xab\x94\xe5\xc2\xd2@!\xe4&\xc4\xff\x00m<\x0fX\xa41T\xf6D\x90M\xc0\xdch\x19\x92\xc3\x8d\xe4MD\xf3\x8bb\xe8$\xdc\xfa\x88\xfb\xe8<\xf9\x95\xfb\xa9\r"E\x10\x05\xc6\xfe\xaa6\x03Jq\xb2\xaeu\x04\xdayE\x84\xf5\xd5\xdb\x08,6B\xad\xbbAI dJI\x03Khu\xa1V\xae}\x12\xb3\xa5\xce\x97\xa1\x93b\xadE\x00\x17\x1do6R\xebd\x828\xd6\xc3\x0f\x9e%\xc7*&\xeb\xb5\xbc\xc6\xb2,\xa8! *\xca\x1c\x05\x19\x06P\x8b0\x10l\x85o\x06\xab\xa9\x0c\x91(J\xcc\xd8\x17\n\x8a\xb9\xf7\xd7\x8d!U\xafb.:8\xebP\xa5\xc0\xb6\xf3q\xe8\xaf\x15\x05\'\xae\xdd5\x8c\xd0vnT\x91s\xe8\xa8\xcaV\xe19E\xeaB\x90\x11\x7fU\x10\xd2F[\\_\xaa\xb6\x15\x95R\xd9\x0c\xf2%\xc1\x98-V=TK\x11cX(6\x9b\xf9\xa9\xf8\x92\x02\x9b\x06\xd7\t\xaa\xd8\xd2\x85\xd4\x81\xbcR\xf6H\x8a\\\xa1\x0b\x18B\x1a\xb0mH\xb9M\xb4\xbdWm\x0b\xad7"$\x86\xdaA\x0e\xa8\xa1\xc4\x94\x8b([\x8dK\x8d\x1dD\x82\x070jh\\m\xb5\xaa"P\x07<\x11a\xd7\xba\xa2\xd9$\x91\x90\xc4!%\x13_J\\u-\x95\x85r|\xa9\xb5\xb8iTX\xb3QZ\x91\x11\x0e\xbc\xdcV\xd6\xe9\n}@\x90\x8e\xb3k\x9f\xfb\xad~\xd0\xc71\xa6\x82m\xa8\xb5\xfc\xd5\x86\xda\xa6K\xb8z\\I\xcd\x91b\xf6\xa8\xc6O5r2\x8a\xb7E\x13\xa5,I+\x8a\xe5\xd2\x95hxo\xe1\xd5Q\xbf%@\x87\xdb\xba\t&\xd9N\xe3\xc4\x7f\xce\x9a\r\xa7\x1cqM \x8b\xa1\'\xf4G\xd6x\xd5\x96!\x15\xb6\xdc<\x9al\x92/\xa1\xb8\xbdj3\xb2\xad\xc9\x05\xd2B\x92,M\xcd\x85\xb5\xa8\x85\x82\xac\x9e52\x99Q\xdc(\xa88yq\xc0\xa3{\xf0\x14\x0cF#eZ\x05\xaeM\x1e\xb5\xd9\xd0\x93\xc3\x85\xe9\xce\x96\x9a\xd1B\xeen\xf3Ta\xb0\x94r\xaa\xbe\xbb\xb5\xa0\x88<\x85]\xc2\x06\xea\x8chojz\xaeW{S\t\xb0\xd7JC\x08A\xce\xdf\xb9\xb2\x87\x1a\x95\xc3p\x95\xeb~5\x03.eI\xb6\x94B\xcef\x89\x03\xd3LF\x97\rx\xbb\x11\x04\x92m\xa5\x81\xa2\xd6w\xd5\x1e\x06\xff\x00\xf0ko}\xb5\xdf\xad\\\xa8\xdb\x88\xbfH\xacSV\x91\xa6.\xe8\xed\x12V\xe3I\xe5\x05\x8bv\xb2\x81\xf8=t.\x17\x89"D\x97b\x95Y\xc6\xc0X\x04\xfb\xa4\x93\xbct\x8a\xb2B\x92\xb4[CX\xdc{\n\x9b\x86cP1\xec5jSQ\xde\x1e7\x1b~fN\x8b)\xeb\x00\xde\xdcmZF\xac\xf4m\x1eHSj\xeb\x15\x9di\x92\xce.\xa5\x93\xccq\x00X\xf4\x83\xfb\xebH\xbb\x14fI\xcc\x9e\x07\xa6\xb3\xf8\x9a\xb95\xa5\xd1\xbd\x06\x93\x12\x19\x8b\xb2\x0b\x0e\x0e\x16\xddA\xe2\xf2\x1a\\$\xbc\xdb\x8c\xa9E)q!N\xa5 \xdc\xe9rN\x94V"\xfefG\x1c\xc9\xaa\xccI\xd0\xac\x01\xa2\xa4\xa4\x9eJ\xc4\x91\xd1\xa5E\x92EF\xd4LD\x81\x15\xf0@K\xc8\xcc\x007\x1a\x8e\x9e5\x95\x9c\xdad\xc4u\x05W\xcc\x93aE\xc1zN2!\xad\xf6\x0chl1\x91\xb0\xaer\x9d\xbf\xc2\xb5\xb4\x15b0\x88\x8b6\x0f:\x95\x1f\xd5\xd3\xec\xac\xd2\xaa\xa3-\x92\xc5\xb4sDF-?\xd5}t\xbdY:\xc1Z@H\xbax^\xb6\xe7c\xb0\xe5\xa9K\xf2\x82\xd3\x9b\xa4\n`\xd8\xe8\xcd\x9b\xb5\x8d\xb6-\xc1m\x8e\xf5^\xb9t\xbe\x99\xdd\x19\x9c\xf1\xd8o6\xaert\xe9\xa9Ym\xd0\xde\x89"\xd5\xd0\x8e\xca8\xb4\xab.!\x05\xc2E\xb9\xc4\x81\xf7\xd0\xab\xd8\xacM)!\x97!\xaf\xa0\x07\xad\xf6\x8a\x9a\xe4Q\xf5">9\xfc1)\x8c\x93\xceu[\xf8TN\xddG(\xd1"\xb4\xb2v\'h\x8eb\x98\x01\xc1}\x0bo!_}\x06\xee\xca\xed\x1b`\x15`\xd2\xfa\x0eTf\xfb*j\xad7\xd4\x97\xf6,e\xf0\xa3)\x16\xb5\n\xbei"\xf7\xabi\x18^)\x1f\xdf\xb0\xd9\xad\xf5\x98\xeb\x1fuT>\x14\xd0%\xd4-\xb3{s\xd2G\xdbR\xba}\x08F\xc9\xe9\xa3\x94\xe1[6\xb1\xd7}V4\xe2TBR\xb4\xa8\xf4\x03V!\xc0\xa6\x88\x1b\xc6\x94\xd02\\5\xd2\xcc\xc6\xeetV\x86\xb59\xafb=v\xacj\x96B\x92@\xb1\x15k\x86\xe3ANr\x12\x8d\x89:,\xee\xf4\xd5\x15`\xde\xd1e9[L\xed\x18N<\xb4H\x10\xa7\x14\xa2G\xc1 \xf3\\\x1d#\xaf\xaa\xb4k}\xa5\xa2\xc5C^\x8a\xc8\xcaa\xb9-eX \x83t\xab\x8aMC\x0b\x12\x9b\x87Les\xb2=\x1d\x1a)\xc6\xcf8\x0e\x92\x9a\xcbC\x95}H\xd5({F\x9a~.\x8c\x1d\x96\xfccF\x16\xa0\x84\xbaw$\x9d\xc0\xd6sh\xb6\x97\x0fe\x94\x8f\x19l\x95\x02N\xbb\xba(\x8f\x08\xc6\x1e#\xe0\xfaC\xac\xbe\x90\xb7\\i\r\x11\xa8Z\x94\xa0-\xe7\xe3\xe8\xaeB\xce\xc48\xeb\xa9\xf1\x89\xc9"\xfc\x01\'\xeb\x15\xa6\xa4\xd4{ei|GPs\x17\x8f\xe4\x88\xcf>\xf2\x12\xb2\xd0\xdez\xb55\x9b\x8eqlv\x08\x0b\x90\x960\xf5\xa9jl!\x17qh\'K\x92E\xae>\xda\x92\x0e\xc5\xe1\xb1y5r!\xc2\x00\xf7\xc5\x95\x8fQ\xd2\xb5\x91\xe0\xb6\xdbb\xe1?Ub\xa9\xc9\xf5\x12\xd5\x1f\xa01p\xb4!\x94%(\x08B@\t\x01J\xd0\r\xdch\xe4\xc6B\x11d\x85\xf9\xc3\x8a\xa9\xf9&@\x1a\xdb\xabN\xdap\x0c\xa7}\xbdb\xb16\xd9!\x89d\xee*p\x7f\x98{)\xc5\xa2-g\x1c\x1ee\x0e\xca\xf1BN\xa8XH\xa6\x94(n]\xe9\x08w&R5+>\x84\xde\xbc\x1bE\xc1\xc8n:[I\xfb\xe9\x96P\xdf\xff\x00>\xba\xf0+\xbe\xfd}4\x01(J.\x00>\xa4\x0e\xda\x93\x93N\xf0}%\x1f\xbe\xa0\xfe\x13\x82\xd2=b\xa4\xcc\xb1\xa6d\x9fY\xa0\tSt\x8eb\xc2O\x99C\xef\xa7)D\xe8\xa5f\xd7\x8esP\xf3\xed~i\xf4U:\xb1\x97c\xe3\x8e1\x8a\xce\x85\x84\xe1i)K2%B{\xf8\xc1 \x15Y\xdd\x1b\x167\x1a\xd5\xb4iJ\xac\xb1\x89\t\xc9E]\x96oa\xd0\x9eI\xe5`\xc2wO\x86\xdd\xef\xeb\x14\x03\xbb3\x829\xee\xb0<8\xdf\x8aF[\xfa\xadZR\x9c\x15Lr\xe9\xc6\xa1\x06m\x98\xb9\xe3m\x14\xdb\xa6\xf7\xac\xee\x1f\xb4\xd8v1\x8a\xcc\x8d\x86\xc8[\xd0! \xaaN(\xb4\x06\xe2\xb7\xd4VN\xfe\x8e\x9f5h|^Dz\xff\x00J\xd5Zl\r\xcd\x88\xc0\x1f7V\x0c\xda\x08\xd2\xedIP\xb7\xfb\xa8\x17|\x1b\xec\xeb\xa4\xab\xc5g6O\xc5\xca\xdd\xe87\xa3\x9a\xdb\xac\x06T\xd7b\xc1\x96\xfc\xd56m\x9a$\'\x9c\n\xf3Xn\xab\x98\xf2\\\x98\x01f\x1c\xe5\x03\xa5\xd5\r\xe4\x7f\xf4\x91Q\xc3\x94\xbe\x8f*\x7f\xc16D_6\x9a\xf0\xbd00\x93}=u\x02\xcc\xc4\x80\xa1\x1dO!IIJP\x8b\x10H\xb9\xb9\xa8\\{\x13E\xc0\x80\xa2mqe\x13\xad\xf5\xe1\xd1Y\xb1e\xd7=+\x02\x8d%$)\x0b\t\xcc\x1cSi_0\xa8n9w_\xae\x9a\xce\x11\x19\x822\xa5Y\xf8kz\xb4Ip\xa1\x04\x81\x98\x81}ocH[XU\xd4\xa1~\x00\n2}\\.B\x88\xe9\xb0IO\xd7S\xa5\xb0\x84\xda\xde\xbaqZ\xd2\x9b\x91\xce\x1d\x14\xd5=e\\\xde\x90\x08\xa4\xb6\xa3\xbe\xfdAT\xd4\xc4l\xf3\x94m\xd0/z\x948\x95\x91r\xad8\x1d\xd4\xeeU\xb4\x0b\x12:u\xa0D&3z\x83b:M*\xa3\xe8\x08)OE\x92;*\\\xe9^\xa2\xc7\xaa\x99d^\xe4\x93\xe9\xd2\x80\x07RV\x83\xaa\x92\xa1\xe6\x15\xe0\xb2nO\n\x9b*r\xdc\x91m\xf7\x14\x89R\x06\x84\\\x1e\x91Hd9\xb3h\x92\xbe\xbdmOJW\xc1\xd2/\xc2\xe6\x94%\xb0\xaei\xd7\xec\xa99\xa7\x80\xb7I\xa0\x08\xc2V\x14\x12\xa77\xf5\xdcS1\xff\x00\x08\x18\x1e\xcb\xe0\xc9\x8d%\xc4O\x9b\x97*\xb0\xf6\x88:\xff\x00Y}\x12,x\x8b\xf5Q\x03(M\xc9\xd3\xaa\xb9t\xf8\xf8_\xfeQD\xa9N\xa9\xf8\xcd\xe2\r\xaa{N6\x02[A\xca\x12\xab\x92s&\xe59\xb4\x16\xbdo\xe0;T\x7f\xa3?!^;5\x9b\x12\x8d\x8f\xdb\x10\xa4N\xd9\x1c"\x1e6\x92\\\xf1Q\x1c\xa0:\xd1<\xd7\x10\x93l\xc3\x81\xf3t\x1at<!\x9d\xbf\xc6\xa5\xf8\xc2\x04}\x8e\xc2$\x98\xb0\xf0\xd8\xc3\x92n[\xa9\xf7N+-\xb9\xa0\xfd\xa0t\xd6\xbbh\xf6}\x9d\xa1e\xa5\x17\x95\x13\x13\x8a\xac\xf0g\xb5\xee\xe3/\x85\x8f\x14\x9e)\xddj\xcfx4\xc4\x83\x18T\xad\x99\x9f\x91\x8ck\x0b\x92\xef\x8c3}\\\x0bYW(\x9e\x91u[N\xae\x9a\xeb\xd8\xc7r]\xa4\xf0\x97\xb3\xdb\r\xca`\xf0\xe3\x17&0\xdf6$4%\xb6[U\xb4J\xd47u\xd8\x13\\\xd9\xcf\x0b3\xe70\xe2\xf1\'qGf\xb8\xbf\xe0cC\x99\xe2\x91R4\xb0\xe6\x0eUg\xce\xae5s\xb5\xdb\x0c\xbcO\xc2\x8c\xc5D\x87\'\xc5\xdf\x861\x05\xad\x84\xa5g\x95\xbeRB\x15\xa2\xc6k\x12\x8b\xdc\xdc\xdb\xa2\xa4\xd9\xe8\x18^\x06\xf4\xe7\xa7\xbb\x84bo<\xd9L\xd6\xe6\xe2(k1\xd7\x9cYu\x9eQ\x07]\xc0\xfa\xf4\xa0\x15\x8f\xff\xd9"""

    print(response_body)
    response_status_line = b'HTTP/1.1 200 OK'
    response_headers = [
        response_status_line,
        b'Content-Type: image/jpg; encoding=utf8',
        bytes("Content-Length: %s" % len(response_body), 'utf-8'),
        b'', response_body,
        b'Connection: close',
        b'\r\n',  # Newline to end headers
    ]

    response = b'\r\n'.join(response_headers) + response_body
    return response


def send_test_response(client_sock, response):
    """Create the test response.

    Args:
        client_sock (socket): the socket to send the request on
        response (str): the response to send

    Returns:
        None
    """
    client_sock.sendall(response)


def get_listen_sock(port):
    """Create a TCP socket, bind it to the requested port, and listen.

    Args:
        port (int): The port to bind to

    Returns:
        The created socket (socket).

    Raises:
        Socket errors
    """
    # create_server is a nice convenience function that calls socket(), bind(),
    # and listen() for the programmer.  However, since it is only available in
    # Python version 3.8, we won't use it.
    # address = ('', port)
    # s = socket.create_server(address, reuse_port=True, dualstack_ipv6=True)

    address = ('', port)
    # Note: Using AF_INET and not AF_INET6 makes this not IPv4/IPv6 compliant
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    s.bind(address)
    s.listen(100)

    return s


def main():
    """A simple HTTP server that is *not* strictly compliant to the HTTP
    protocol.  In particular, this server entirely ignores the incoming message
    and returns a static response.  This server is primiarly useful for
    experimenting with whether or not a static response is HTTP compliant.

    Args: None

    Returns: None
    """
    # Use argparse to allow for easily changing the port
    parser = argparse.ArgumentParser(description='Simple server to test '
                                                 'edge-cases in the HTTP protocol.')
    parser.add_argument('--port', required=True, type=int,
                        help='The port to listen on.')
    args = parser.parse_args()
    port = args.port

    # Create the listening socket
    server_sock = get_listen_sock(port)

    while True:
        # Accept the connection
        client_sock, client_addr = server_sock.accept()

        # Ignore any request (not protocol compliant)

        # Get the test response
        response = get_test_response()

        # Print sending response for optional debugging
        # print('Sending response:')
        # print(response)

        # Send the rest response
        send_test_response(client_sock, response)

        # Close the connection for garbage collection
        client_sock.close()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        print(traceback.print_exception(exc_type, exc_value, exc_traceback, limit=5, file=sys.stdout))
