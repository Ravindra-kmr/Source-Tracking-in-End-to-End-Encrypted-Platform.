from tabnanny import check
from user import UserTreeLinkable
from platform import PlatformTreeLinkable, AES_KEY, CTR_NONCE, RSA_KEY_SIZE

from cryptography.hazmat.primitives import serialization

from utils import check_commit, COMMIT_SIZE, R_SIZE, make_commit, verify_sign, log_file, BOT

def main():

    # Setup
    bob = UserTreeLinkable()
    alice = UserTreeLinkable()
    collin = UserTreeLinkable()

    platform = PlatformTreeLinkable()

    # New UserTreeLinkable Registration
    users = set()
    users.add(bob.userid)
    users.add(alice.userid)

    # Author a new message
    message = b"Hello!"
    commit, e = bob.author_msg(message)
    print "Message Sent Successfully. \ncommit: ", commit, "\ne: ", e
    pd = platform.generate_pd(commit, bob.userid)
    print "Platform data for forward message, pd: ", pd
    
    # Receive a message
    message, fd = alice.receive_msg(pd)
    print "Received message: ", message, "\n FD: ", fd

    # Forward a message
    commit, e = alice.forward_msg(message, fd)
    print "Message Forwarded Successfully. \ncommit: ", commit, "\ne: ", e

    pd = platform.generate_pd(commit, alice.userid)
    print "Platform data for forward message, pd: ", pd

    # Report Message
    message, fd = collin.receive_msg(pd)
    source_id = platform.report_msg(fd)

    print "Reporting Succeeded! Source of the message is ", source_id


class TestPlatform():

    def __init__(self):
        self.platform = PlatformTreeLinkable(AES_KEY, CTR_NONCE, RSA_KEY_SIZE)

    def register_user(self):
        userid = "jude"
        self.platform.register_user(userid)
        if userid in self.platform.users:
            print "register_user succeeded"
        else:
            print "register_user failed"
    
    def generate_pd(self):
        m = "hello jude"
        commit, r = make_commit(m)

        userid = "Ravi"
        md=None
        sigma, src = self.platform.generate_pd(commit, userid, md)
        if verify_sign(self.platform.public_key, sigma, commit + src):
        
            print "generate_pd succeeded"
        else:
            print "generate_pd failed"


    def report_msg(self):
        m = "hello jude"
        commit, r = make_commit(m)
        userid = "Ravi"
        md=None

        sigma, src = self.platform.generate_pd(commit, userid, md)
        fd = (sigma, src, commit, r)
        
        reported_userid, md = self.platform.report_msg(fd, m)

        if reported_userid == userid:
            print "report_msg succeeded"
        else:
            print "report_msg failed"


class TestUser():

    def __init__(self):

        plat_pub_key_file = "/home/jude/Mtech/Sem_2/NS/Project/src/tree_linkable/platform_pub_key.pem"


        with open(plat_pub_key_file, 'rb') as f:
            self.platform_pub_key = serialization.load_pem_public_key(f.read())

        self.alice = UserTreeLinkable("alice", "", 11111, plat_pub_key_file)
        self.bob = UserTreeLinkable("bob", "", 11111, plat_pub_key_file)
        self.chuck = UserTreeLinkable("chuck", "", 11111, plat_pub_key_file)
        
        print "Created dummy users"
        return

    def author_msg(self):

        m = "Hello!!"
        msg_id = str(self.alice.name) + str(1)
        msg = self.alice.author_msg(m, msg_id)

        success = True

        if m != msg[0]:
            print "author_msg returned different message text"
            success = False

        if BOT != msg[1]:
            print "author_msg returned different BOT value for FD"
            success = False 

        commit = msg[2]
        r = msg[3]

        if not check_commit(commit, m, r):
            print "author_msg returned invalid commit"
            success = False 

        if success:
            print "author_msg succeeded!"
        else:
            print "author_msg failed!"
        
        return

    def forward_msg(self):
        
        m = "Hello!!"
        msg_id = str(self.alice.name)  + str(1)
        msg = self.alice.author_msg(m, msg_id)

        fd = self.bob.receive_msg(msg, msg_id)

        msg_id = "bob:1"
        fwd = self.bob.forward_msg(m, fd, msg_id)

        m_fwd, fd_fwd, commit_fwd, r_fwd = fwd

        success = True
        
        if m_fwd != m:
            success = False
            print "forward_msg returned text msg does not match original"

        if fd_fwd != fd:
            success = False
            print "forward_msg returned fd does not match original"

        if not check_commit(commit_fwd, BOT, r_fwd):
            success = False
            print "forward_msg returned commit is not valid"


        fwd_fd = self.chuck.receive_msg(fwd, msg_id)

        fwd_sigma, fwd_src, fwd_commit, fwd_r = fwd_fd


        if not check_commit(fwd_commit, m_fwd, fwd_r):
            print "forward_msg returned invalid commit on fwd_fd"
            success = False 

        if not verify_sign(
                        self.platform_pub_key, 
                        fwd_sigma, 
                        fwd_commit + fwd_src):
            print "forward_msg fwd_fd signature failed verification"
            success = False
        
        if success:
            print "forward_message succeeded!"
        else:
            print "forward_message failed!"



    def receive_msg(self):

        m = "Hello!!"
        msg_id = str(self.alice.name) + str(1)
        msg = self.alice.author_msg(m, msg_id)

        fd = self.bob.receive_msg(msg, msg_id)
        
        sigma, src, commit, r = fd

        success = True

        if not check_commit(commit, m, r):
            print "receive_msg returned invalid commit"
            success = False 

        if not verify_sign(
                        self.platform_pub_key, 
                        sigma, 
                        commit + src):
            print "Signature failed verification"
            success = False
        
        if success:
            print "receive_message succeeded!"
        else:
            print "receive_message failed!"

        return
 

    def message_fds(self):
        return self.msg_fd_map

    def report_msg(self):
        
        m = "Hello!!"
        msg_id = str(self.alice.name)  + str(1)
        msg = self.alice.author_msg(m, msg_id)

        fd = self.bob.receive_msg(msg, msg_id)

        msg_id = "bob:1"
        fwd = self.bob.forward_msg(m, fd, msg_id)

        m_fwd, fd_fwd, commit_fwd, r_fwd = fwd

        success = True
        
        if m_fwd != m:
            success = False
            print "report_msg returned text msg does not match original"

        if fd_fwd != fd:
            success = False
            print "report_msg returned fd does not match original"

        if not check_commit(commit_fwd, BOT, r_fwd):
            success = False
            print "report_msg returned commit is not valid"


        fwd_fd = self.chuck.receive_msg(fwd, msg_id)

        fwd_sigma, fwd_src, fwd_commit, fwd_r = fwd_fd


        if not check_commit(fwd_commit, m_fwd, fwd_r):
            print "report_msg returned invalid commit on fwd fd"
            success = False 

        if not verify_sign(
                        self.platform_pub_key, 
                        fwd_sigma, 
                        fwd_commit + fwd_src):
            print "report_msg fwd fd signature failed verification"
            success = False
        
        userid = self.chuck.report(m_fwd, fwd_fd)

        print "Reported user: ", userid

        if success:
            print "receive_message succeeded!"
        else:
            print "receive_message failed!"

if __name__ == "__main__":

    # print "Testing Platform ..."
    # test = TestPlatform()
    # test.register_user()
    # test.generate_pd()
    # test.report_msg()
    # print "Done"

    print "Testing User ..."
    test = TestUser()
    test.author_msg()
    test.receive_msg()
    test.forward_msg()
    test.report_msg()
    print "Done"
    # main()