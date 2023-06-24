
def get_port(port_file):
    """
    :param port_file: path to a local file containing the port number
    :return: the number from the file or None if there was a problem
    """
    port = None
    try:
        with open(port_file) as f:
            data = f.read()
            port = int(data)

    except FileNotFoundError:
        print(f"Warning! {port_file} file is missing in directory")
    except ValueError:
        print("Warning in port file. Not a number")
    except:
        print(f"Warning! unknown problem with {port_file} file")
    finally:
        return port


