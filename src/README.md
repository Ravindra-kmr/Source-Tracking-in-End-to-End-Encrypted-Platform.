
# README

## Directory Structure

The code is contained in the **src** folder. 

1. **tree_linkable** contains:
   1. *platform.py*:  Contains the class capturing the platform side of the
      source-tracking scheme. It also contains a main function that allocates
      connections to each user and another function for handling their interaction.
   2. *user.py*: Contains the class capturing the user side of the source-tracking
      scheme.
   2. *utils.py*: Contains the helper functions for source tracking.
   3. *message_format.md*: Contains all the message types that are passed between
      platform and user sides of the source-tracking scheme.

   4. *test_protocol.py*: Contains tests for platform and user classes.
   5. *platform_pub_key.pem*: Contains the public key of the current instance of
      platform.
    
2. *axochat.py*: Contains functions for sending and receiving messages among users
   utilizing the ratchet encryption. The user part of the source-tracking scheme is
   used here.

3. *<*>.pkl*: Auxiliary file for persisting fds across chat sessions.
4. *<*>.db*: Auxiliary file for persisting chat messages across sessions.

## Usage

Initially, a platform instance needs to be setup followed the server side of the messaging pair and then the client side of the messaging pair.

* To start platform instance:
  1. Start a terminal.
  2. cd into the tree-linkable folder inside the src folder.
  3. Run: `python platform.py -p <port-number>`
     1. platform listens at the given port number.

* For setting up messaging pair (a, b):
  1. Start 2 terminals.
  2. In the first terminal (setting up server side (a) of ratchet scheme):
     1. cd into src folder.
     2. `python axochat.py -s`
     3. The following choice must be entered:
        1. "Enter your nick: " any string as a nickname of a.
        2. "Enter the nick of the other party: " nickname of b.
        3. "Enter the platform IP address: " (leave as blank and press enter if platform is on the same system).
        4. "Enter the platform port: " port number of platform instance.
        5. "TCP port (1 for random choice, 50000 is default): " The port on which a will listen to for b.

  3. In the second terminal (setting up client side of ratchet scheme):
     1. cd into src folder.
     2. `python axochat.py -c`
     3. Enter the appropriate choices as given for server side. For other choices:
        1. "Enter a 's ratchet key: " copy and paste the ratchet key shown in first terminal.
        2. "Enter the other client's ip address: " ip-address of server a (leave as blank and press enter if server is on the same system).
        3. "Enter the other client's port number: " Port number on which a is listening.


### Sending a Message

```
message (press enter)
```


### Forwarding a Message.

```
Fwd: <Username>:<msgid> (press enter)
```

### Reporting a message.

```
Report: <Username>:<msgid> (press enter)
```