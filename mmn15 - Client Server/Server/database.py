import sqlite3


"""
create tables based on assignment instructions
"""
def create_files(conn):
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS files(
            ID CHAR(16),
            FileName CHAR(255),
            FilePath CHAR(255),
            Verified INTEGER(1));
    """)
    conn.commit()


def create_clients(conn):
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS clients(
            ID CHAR(16) NOT NULL PRIMARY KEY,
            Name CHAR(255) NOT NULL,
            PublicKey CHAR(160),
            LastSeen Date,
            AESKey CHAR(128));
    """)
    conn.commit()


class Database:
    """
    just some code to make the communication with database easier
    """
    def __init__(self, database_name):
        self.db = database_name
        conn = sqlite3.connect(self.db)
        conn.text_factory = bytes

        # in case any of the tables don't exist, we create them
        create_clients(conn)
        create_files(conn)
        conn.close()

    def fetch_data(self, table, column=None):
        """
        fetch big chunks of data from database
        :param table: specific table to fetch from
        :param column: columns to fetch (None for all)
        :return: result from qury
        """
        conn = sqlite3.connect(self.db)
        cur = conn.cursor()

        if column is None:
            cur.execute(f"SELECT * FROM {table}")
        else:
            cur.execute(f"SELECT {column} FROM {table}")

        result = cur.fetchall()
        conn.close()
        return result

    def query(self, query, args):
        """
        query something from database
        :param query: SQL statement
        :param args: array of arguments
        :return: (bool) succeeded?
        """
        conn = sqlite3.connect(self.db)
        try:
            conn.execute(query, args)
            conn.commit()
        except Exception as e:
            print(f"Exception in query - {e}")
            return False
        conn.close()
        return True

    def query_with_result(self, query, args):
        """
        query something from database
        :param query: SQL statement
        :param args: array of arguments
        :return: result from query
        """
        conn = sqlite3.connect(self.db)
        res = None
        try:
            cur = conn.cursor()
            cur.execute(query, args)
            res = cur.fetchall()
        except Exception as e:
            print(f"Exception in query - {e}")
        conn.close()
        return res

    def print_data(self, table):
        """
        unused in the code, but this just prints data from the database
        :param table: table to read from
        """
        conn = sqlite3.connect(self.db)
        cur = conn.cursor()
        cur.execute(f"SELECT * FROM {table}")
        print(cur.fetchall())
        conn.close()
