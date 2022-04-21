# Message-Format

## Scheme 1

1. 100:
   1. Sender: User
   2. Receiver: User
   3. Info: data to be sent to another user.
2. 101:
   1. Sender: User
   2. Receiver: Platform
   3. Info: registering new-user
3. 102:
   1. Sender:
      1. User.
   2. Receiver:
      1. Platform
   3. Info: Sending commit.
4. 103:
   1. Sender:
      1. Platform.
   2. Receiver:
      1. User:
   3. Info:
      1. pd
5. 999:
   1. Sender:
      1. Any
   2. Receiver:
      1. Any
   3. Info:
      1. Error

## Components

1. Code:
   1. Determines which protocol the message belongs to.
2. Protocol-Specific data.