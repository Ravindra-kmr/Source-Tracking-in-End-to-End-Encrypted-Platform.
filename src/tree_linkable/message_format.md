# Message-Format

## Scheme 1

1. Code 100:
   1. Sender: User
   2. Receiver: User
   3. Info: msg to be sent to another user.
   4. Msg-Size: Unbounded, delimited by 'EOP' + 3

2. Code 101:
   1. Sender: User
   2. Receiver: Platform
   3. Info: userid registration
   4. Msg-Size: Max-size(userid) + 3

3. Code 102:
   1. Sender:
      1. User.
   2. Receiver:
      1. Platform
   3. Info: Sending commit.
   4. Msg-Size: Commit-Size + 3

4. 103:
   1. Sender:
      1. User.
   2. Receiver:
      1. Platform
   3. Info:
      1. Request pd for message having the given id 
   4. Msg-Size: msgid + 3

5. Code 104:
   1. Sender:
      1. Platform.
   2. Receiver:
      1. User.
   3. Info:
      1. pd
   4. Msg-Size: SIG-SIZE + SRC_SIZE + 3

6. Code 105:
   1. Sender:
      1. User.
   2. Receiver:
      1. Platform
   3. Info:
      1. Reporting a message to platform.
   4. Msg-size:
      1. fd  + size(msg)

6. Code 106:
   1. Sender:
      1. Platform.
   2. Receiver:
      1. User
   3. Info:
      1. Return source id.
   4. Msg-size:
      1. size(userid)
   
7. Code 999:
   1. Sender:
      1. Any
   2. Receiver:
      1. Any
   3. Info:
      1. Error
   4. Msg-Size: Unbounded, delimited by EOP


## Components

1. Code:
   1. Determines which protocol the message belongs to.
2. Protocol-Specific data.