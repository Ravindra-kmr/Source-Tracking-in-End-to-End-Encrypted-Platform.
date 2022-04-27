from platform import platform
from tree_linkable.user import UserTreeLinkable
from tree_linkable.platform import Platform

def main():

    # Setup
    bob = UserTreeLinkable()
    alice = UserTreeLinkable()
    collin = UserTreeLinkable()

    platform = Platform()

    # New UserTreeLinkable Registration
    users = set()
    users.add(bob.userid)
    users.add(alice.userid)

    # Author a new message
    message = b"Hello!"
    commit, e = bob.author_msg(message)
    print(f"Message Sent Successfully. \ncommit: {commit}, \ne: {e}")
    pd = platform.generate_pd(commit, bob.userid)
    print(f"Platform data for forward message, pd: {pd}")
    
    # Receive a message
    message, fd = alice.receive_msg(pd)
    print(f"Received message: {message}\n FD: {fd}")

    # Forward a message
    commit, e = alice.forward_msg(message, fd)
    print(f"Message Forwarded Successfully. \ncommit: {commit}, \ne: {e}")

    pd = platform.generate_pd(commit, alice.userid)
    print(f"Platform data for forward message, pd: {pd}")

    # Report Message
    message, fd = collin.receive_msg(pd)
    source_id = platform.report_msg(fd)

    print(f"Reporting Succeeded! Source of the message is {source_id}")


if __name__ == "__main__":
    main()