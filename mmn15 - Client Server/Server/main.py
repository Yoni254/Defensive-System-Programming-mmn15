import server
import utils
import database

DEFAULT_PORT = 1234
PORT_FILE = "port.info"

"""
   code for mmn15 - Defensive System Programing
   course number 20937

   this is a simple Server - Client code for exchanging encrypted files based on users
   files are kept inside folders named as the user id of the client that sent them

   @author yonatan tzukerman
   @date 23/03/2023
"""

if __name__ == "__main__":
    # parse port (or go to default)
    port = utils.get_port(PORT_FILE)
    if port is None:
        port = DEFAULT_PORT

    # start up the server
    server = server.Server(port)
    server.start()




