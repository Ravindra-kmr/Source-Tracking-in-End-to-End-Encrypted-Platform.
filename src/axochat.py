#!/usr/bin/env python

import os.path
import hashlib
import socket
import threading
import sys
import curses
import json
from curses.textpad import Textbox
from random import randint
from contextlib import contextmanager
from pyaxo import Axolotl
from time import sleep
from getpass import getpass
from binascii import a2b_base64 as a2b
from binascii import b2a_base64 as b2a
import os
import pickle
import base64
from Tkinter import *
import ttk
"""
Standalone chat script using libsodium for encryption with the Axolotl
ratchet for key management.

Usage:
1. One side starts the server with:
     axochat.py -s

2. The other side connects the client to the server with:
     axochat.py -c

3. Both sides need to input the same master key. This can be any
   alphanumeric string. Also, the server will generate a handshake
   key that is a required input for the client.

4. .quit at the chat prompt will quit (don't forget the "dot")

Port 50000 is the default port, but you can choose your own port as well.

Axochat requires the Axolotl module at https://github.com/rxcomm/pyaxo

Copyright (C) 2014-2016 by David R. Andersen <k0rx@RXcomm.net>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
"""
pwd = os.getcwd()
print pwd
sys.path.append(pwd)

from tree_linkable.user import UserTreeLinkable



@contextmanager
def socketcontext(*args, **kwargs):
    s = socket.socket(*args, **kwargs)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    yield s
    s.close()

class _Textbox(Textbox):
    """
    curses.textpad.Textbox requires users to ^g on completion, which is sort
    of annoying for an interactive chat client such as this, which typically only
    reuquires an enter. This subclass fixes this problem by signalling completion
    on Enter as well as ^g. Also, map <Backspace> key to ^h.
    """
    def __init__(*args, **kwargs):
        Textbox.__init__(*args, **kwargs)

    def do_command(self, ch):
        if ch == 10: # Enter
            return 0
        if ch == 127: # Enter
            return 8
        return Textbox.do_command(self, ch)

def validator(ch):
    """
    Update screen if necessary and release the lock so receiveThread can run
    """
    global screen_needs_update
    try:
        if screen_needs_update:
            curses.doupdate()
            screen_needs_update = False
        return ch
    finally:
        lock.release()
        sleep(0.01) # let receiveThread in if necessary
        lock.acquire()

def windows():
    stdscr = curses.initscr()
    curses.noecho()
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(3, 2, -1)
    curses.cbreak()
    curses.curs_set(1)
    (sizey, sizex) = stdscr.getmaxyx()
    input_win = curses.newwin(8, sizex, sizey-8, 0)
    output_win = curses.newwin(sizey-8, sizex, 0, 0)
    input_win.idlok(1)
    input_win.scrollok(1)
    input_win.nodelay(1)
    input_win.leaveok(0)
    input_win.timeout(100)
    input_win.attron(curses.color_pair(3))
    output_win.idlok(1)
    output_win.scrollok(1)
    output_win.leaveok(0)
    return stdscr, input_win, output_win

def closeWindows(stdscr):
    curses.nocbreak()
    stdscr.keypad(0)
    curses.echo()
    curses.endwin()

def usage():
    print 'Usage: ' + sys.argv[0] + ' -(s,c)'
    print ' -s: start a chat in server mode'
    print ' -c: start a chat in client mode'
    exit()

def receiveThread(sock, user, stdscr, input_win, output_win,convdict):
    global screen_needs_update, a
    while True:
        data = ''
        while data[-3:] != 'EOP':
            rcv = sock.recv(1024)

            if not rcv:
                # print msg


                input_win.move(0, 0)
                senderDB=open("../dump_files/"+NICK+'.db','w')
                json.dump(convdict,senderDB, sort_keys=True, indent=4)
                senderDB.close()
                pickle.dump(msgId_fd_map, fd_file)
                input_win.addstr('Disconnected - Ctrl-C to exit!')
                input_win.refresh()
                sys.exit()
            data = data + rcv
        data_list = data.split('EOP')
        # data_list[0] = data_list[0].strip()
        lock.acquire()
        (cursory, cursorx) = input_win.getyx()
        for data in data_list:
            if data != '':
                msg = a.decrypt(data)
                   
                data, msg = pickle.loads(a2b(msg))
                # print "\nreceived msg ", msg, "\n"
                # sleep(2)

                conv_list = data.split(':>',1)
                sender=conv_list[0].strip()
                conv_list=conv_list[1].split(':',1)
                msgid=conv_list[0].strip()
                
                # Get pd from platform
                unique_msgid = sender+ ":" + msgid
                if "Fwd:" in conv_list[1]:
                    m = conv_list[1].split(':',1)
                    m = m[1].strip()
                    msg = (m, msg[1], msg[2], msg[3])
                    # print "message forwarded, ", msg
                
                fd = user.receive_msg(msg, unique_msgid)
                msgId_fd_map[unique_msgid] = fd
                # print "\nmsg_fd_map: ", msgId_fd_map, "\n"
                # sleep(3)
                msg = data
                
                if 'Fwd:' in conv_list[1]:
                    conv_list = conv_list[1].split('Fwd:',1)
                if sender not in convdict.keys():
                    convdict[sender] = {}
                convdict[sender][msgid]=conv_list[1].strip()
                # senderDB.write(msg)
                output_win.addstr(msg)
                
        input_win.move(cursory, cursorx)
        input_win.cursyncup()
        input_win.noutrefresh()
        output_win.noutrefresh()
        sleep(0.01) # write time for axo db
        screen_needs_update = True
        lock.release()
def ReportGUI(detail):
    Window = Tk()
    Window.withdraw()
    login = Toplevel()
    login.title("Report Information")
    login.resizable(width = True,
                         height = True)
    login.configure(width = 400,
                         height = 200)
    pls = Label(login,
                   text = detail,
                   justify = CENTER,
                   font = "Helvetica 14 bold")
                
    pls.place(relheight = 0.5,
                   relx = 0.05,
                   rely = 0.05)
    # print "\nThe original author is ", source_id
    # sleep(5)
    Window.mainloop()
    sleep(60)

def chatThread(sock, user):
    fwd_messageids = ""
    msgid = 1
    unique_msgid = ''
    if os.path.isfile("../dump_files/"+NICK+'.db'):
        senderDB=open("../dump_files/"+NICK+'.db','r')
        convdict = json.load(senderDB)
        senderDB.close()
        convdict[OTHER_NICK] = {}
    else:
        convdict = {}
    global screen_needs_update, a
    stdscr, input_win, output_win = windows()
    input_win.addstr(0, 0, NICK + ':> '+ str(msgid)+': ')
    msgid+=1
    textpad = _Textbox(input_win, insert_mode=True)
    textpad.stripspaces = True
    t = threading.Thread(target=receiveThread, args=(sock, user, stdscr, input_win,output_win,convdict))
    t.daemon = True
    t.start()
    try:
        while True:
            lock.acquire()
            data = textpad.edit(validator)
            # temp_data = data.split(':',2)
            # temp_data[2] = temp_data[2].replace('\n', '')
            # temp_data[2] = temp_data[2].strip()
            # if temp_data[2] is '':
            #     input_win.clear()
            #     input_win.addstr(NICK+':> '+ str(msgid)+': ')
            #     input_win.move(0, len(NICK)+len(':> '+ str(msgid)+': '))
            #     input_win.cursyncup()
            #     input_win.noutrefresh()
            #     screen_needs_update = True
            #     sleep(0.01) # write time for axo db
            #     lock.release()
            #     continue;
            if (NICK+':>' in data) and ('.quit' in data):
                senderDB=open("../dump_files/"+NICK+'.db','w')
                json.dump(convdict,senderDB, sort_keys=True, indent=4)
                senderDB.close()
                closeWindows(stdscr)
                pickle.dump(msgId_fd_map, fd_file)
                sys.exit()
            if 'Fwd:' in data:
                # print convdict
                data_list = data.split('Fwd:',1)
                header = data_list[0]
                data_list = data_list[1].split(':',1)
                originalauthor = data_list[0].strip()
                msgtosendID = data_list[1].strip()
                if originalauthor in convdict.keys():
                    if msgtosendID in convdict[originalauthor].keys():
                        fwd_messageids = originalauthor + ":" + msgtosendID
                        data = header + 'Fwd: '+str(convdict[originalauthor][msgtosendID])
                    else:
                        input_win.clear()
                        input_win.addstr(NICK+':> '+ str(msgid)+': ')
                        input_win.move(0, len(NICK)+len(':> '+ str(msgid)+': '))
                        input_win.cursyncup()
                        input_win.noutrefresh()
                        screen_needs_update = True
                        sleep(0.01) # write time for axo db
                        lock.release()
                        continue;
                else:
                    input_win.clear()
                    input_win.addstr(NICK+':> '+ str(msgid)+': ')
                    input_win.move(0, len(NICK)+len(':> '+ str(msgid)+': '))
                    input_win.cursyncup()
                    input_win.noutrefresh()
                    screen_needs_update = True
                    sleep(0.01) # write time for axo db
                    lock.release()
                    continue;
            if 'Report:' in data:
                data_list = data.split('Report:',1)
                header = data_list[0]
                data_list = data_list[1].split(':',1)
                fwdauthor = data_list[0].strip()
                fwdmsgID = data_list[1].strip()
                report_unique_msgid = fwdauthor+ ":" + fwdmsgID;
                
                # print "msg_fd_map: ", msgId_fd_map
                # sleep(2)
                # Calling report method
                
                detail = ""
                try:
                    actualmsg = convdict[fwdauthor][fwdmsgID]
                    fd = msgId_fd_map[report_unique_msgid]
                    source_id = user.report(actualmsg, fd)
                    detail = "The original author is: " + source_id
                except KeyError:
                    detail = "Reporting Failed. Unknown Message ID!"
                    # print "Reporting Failed. Unknown Message ID!"
                   #  pls = Label(login,
                   # text = "Reporting Failed. Unknown Message ID!",
                   # justify = CENTER,
                   # font = "Helvetica 14 bold")
                
                   #  pls.place(relheight = 0.15,
                   #                 relx = 0.3,
                   #                 rely = 0.07)
                
                t1 = threading.Thread(target=ReportGUI, args=(detail,))
                t1.daemon = True
                t1.start()
                sleep(5)
                input_win.clear()
                input_win.addstr(NICK+':> '+ str(msgid)+': ')
                input_win.move(0, len(NICK)+len(':> '+ str(msgid)+': '))
                input_win.cursyncup()
                input_win.noutrefresh()
                screen_needs_update = True
                sleep(0.01) # write time for axo db
                lock.release()
                continue;
            input_win.clear()
            input_win.addstr(NICK+':> '+ str(msgid)+': ')
            output_win.addstr(data.replace('\n', '') + '\n', curses.color_pair(3))
            output_win.noutrefresh()
            input_win.move(0, len(NICK)+len(':> '+ str(msgid)+': '))
            input_win.cursyncup()
            input_win.noutrefresh()
            screen_needs_update = True
            data = data.strip()
            data = data.replace('\n', '')
            data = data+'\n'
            try:
                # Generate Commmit and send to platform.
                unique_msgid = NICK+":"+str(msgid - 1);
                # print "Unique Message ID", unique_msgid
                # sleep(3)
                m_text = data.split(':>',1)
                m_text = m_text[1].split(':',1)
                m_text= m_text[1].strip()
                if 'Fwd:' in data:
                    # fwd_id = 
                    fd = msgId_fd_map[fwd_messageids]
                    msg = user.forward_msg(m_text, fd, unique_msgid)
                else:
                    msg = user.author_msg(m_text, unique_msgid)

                # print "Data to sent", data
                # sleep(3)
                data_to_send = b2a(pickle.dumps((data, msg)))
                # data = data.strip()
                sock.send(a.encrypt(data_to_send) + 'EOP')
                msgid+=1
            except socket.error:
                pickle.dump(msgId_fd_map, fd_file)
                
                input_win.addstr('Disconnected')
                input_win.refresh()
                closeWindows(stdscr)
                sys.exit()
            except IndexError:
                sys.exit()
            sleep(0.01) # write time for axo db
            lock.release()
    except KeyboardInterrupt:
        closeWindows(stdscr)


def getPasswd(nick):
    return '1'

if __name__ == '__main__':
    global a
    try:
        mode = sys.argv[1]
    except:
        usage()

    # if mode == '-s':
    #     NICK = "j"
    #     OTHER_NICK = "r"
    # else:
    #     NICK = "r"
    #     OTHER_NICK = "j"

    NICK = raw_input('Enter your nick: ')
    OTHER_NICK = raw_input('Enter the nick of the other party: ')
    # mkey = getpass('Enter the master key: ')
    mkey = ""
    lock = threading.Lock()
    screen_needs_update = False
    HOST = ''

    fd_file_name = "fd_file_{0}.pkl".format(NICK)
    
    try:
        fd_file = open("../dump_files/"+fd_file_name, "r+")
        msgId_fd_map = pickle.load(fd_file) 
    
    except IOError:
        fd_file = open("../dump_files/"+fd_file_name, "w")
        msgId_fd_map = {}
    except EOFError:
        msgId_fd_map = {}

    platform_ip = raw_input("Enter platform IP address: ")
    # platform_ip = ''
    platform_port = int(raw_input("Enter platform port number: "))
    # platform_port = 11111
    # platform_pub_key_file = (raw_input("Enter platform public key file: "))
    platform_pub_key_file = "tree_linkable/platform_pub_key.pem"

    user = UserTreeLinkable(NICK, platform_ip, platform_port, platform_pub_key_file)
    print "Connected to Source-Tracking Platform"

    if mode == '-s':
        while True:
            try:
                PORT = raw_input('TCP port (1 for random choice, 50000 is default): ')
                PORT = int(PORT)
                # PORT = 22222
                break
            except ValueError:
                PORT = 50000
                break
        if PORT >= 1025 and PORT <= 65535:
            pass
        elif PORT == 1:
            PORT = 1025 + randint(0, 64510)
            print 'PORT is ' + str(PORT)
        a = Axolotl(NICK,
                    dbname=OTHER_NICK+'.db',
                    dbpassphrase=None,
                    nonthreaded_sql=False)
        a.createState(other_name=OTHER_NICK,
                      mkey=hashlib.sha256(mkey).digest(),
                      mode=False)
        print 'Your ratchet key is: %s' % b2a(a.state['DHRs']).strip()
        print 'Send this to %s...' % OTHER_NICK

        print 'Waiting for ' + OTHER_NICK + ' to connect...'
        with socketcontext(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((HOST, PORT))
            s.listen(1)
            conn, addr = s.accept()
            chatThread(conn, user)

    elif mode == '-c':
        rkey = raw_input('Enter %s\'s ratchet key: ' % OTHER_NICK)
        a = Axolotl(NICK,
                    dbname=OTHER_NICK+'.db',
                    dbpassphrase=None,
                    nonthreaded_sql=False)
        a.createState(other_name=OTHER_NICK,
                      mkey=hashlib.sha256(mkey).digest(),
                      mode=True,
                      other_ratchetKey=a2b(rkey))




        HOST = raw_input("Enter the other client's ip address: ")
        try:
            PORT = raw_input("Enter other client's port number(50000 is default): ")
            PORT = int(PORT)
            # PORT = 22222
        except ValueError:
            PORT = 50000
        print 'Connecting to ' + HOST + '...'
        with socketcontext(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            chatThread(s, user)
        

    else:
        usage()
