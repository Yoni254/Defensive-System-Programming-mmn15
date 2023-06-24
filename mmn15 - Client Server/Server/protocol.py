import struct
from enum import Enum

"""
Handles all protocols for the program

lots of consts and classes for the different protocols defined in the assignment
there aren't many comments here because the code is fairly repetitive
"""

DEFAULT = 0
DEFAULT_STR = b""
SERVER_VERSION = 3
CLIENT_ID_SIZE = 16
HEADER_SIZE = 7
REQUEST_HEADER_SIZE = (CLIENT_ID_SIZE + HEADER_SIZE)  # in bytes

NAME_SIZE = 255
PUBLIC_KEY_SIZE = 160
CONTENT_SIZE_SIZE = 4  # post encryption
CHECK_SUM_SIZE = 4
SYMMETRIC_KEY_SIZE = 16  # byte


class RequestCodes(Enum):
    REQUEST_REGISTRATION = 1100
    REQUEST_PUBLIC_KEY = 1101
    REQUEST_LOGIN = 1102
    REQUEST_SEND_FILE = 1103
    REQUEST_VALID_CRC = 1104
    REQUEST_WARNING_CRC = 1105
    REQUEST_ERROR_CRC = 1106


class ResponseCodes(Enum):
    RESPONSE_REGISTRATION = 2100
    RESPONSE_FAILED_REGISTRATION = 2101
    RESPONSE_PUBLIC_KEY = 2102
    RESPONSE_FILE = 2103
    RESPONSE_RECEIVED = 2104
    RESPONSE_LOGIN = 2105
    RESPONSE_FAILED_LOGIN = 2106
    RESPONSE_ERROR = 2107


class RequestHeader:
    def __init__(self):
        self.client_id = DEFAULT_STR
        self.version = DEFAULT
        self.code = DEFAULT
        self.payload_size = DEFAULT

    def unpack(self, data):
        res = False
        try:
            self.client_id = struct.unpack(f"<{CLIENT_ID_SIZE}s", data[:CLIENT_ID_SIZE])[0]
            # B - unsigned char (1), H - unsigned short (2), L - unsigned long (4)
            self.version, self.code, self.payload_size = struct.unpack("<BHL", data[CLIENT_ID_SIZE:REQUEST_HEADER_SIZE])
            res = True
        except:
            self.__init__()
        finally:
            return res


class ResponseHeader:
    def __init__(self, code):
        self.version = SERVER_VERSION
        self.code = code
        self.payload_size = DEFAULT

    def pack(self):
        try:
            return struct.pack("<BHL", self.version, self.code, self.payload_size)
        except:
            return DEFAULT_STR


"""
==================

    REQUESTS

==================
"""


class RegistrationRequest:
    def __init__(self):
        self.header = RequestHeader()
        self.name = DEFAULT_STR

    def unpack(self, payload):
        if not self.header.unpack(payload):
            return False
        try:
            offset = REQUEST_HEADER_SIZE
            name_data = payload[offset:offset + NAME_SIZE]
            self.name = str(struct.unpack(f"<{NAME_SIZE}s", name_data)[0].partition(b'\0')[0].decode('utf-8'))
            return True
        except:
            self.name = DEFAULT_STR
            return False


class PublicKeyRequest:
    def __init__(self):
        self.header = RequestHeader()
        self.name = DEFAULT_STR
        self.public_key = DEFAULT_STR

    def unpack(self, payload):
        if not self.header.unpack(payload):
            return False
        try:
            offset = REQUEST_HEADER_SIZE

            name_data = payload[offset:offset + NAME_SIZE]
            self.name = str(struct.unpack(f"<{NAME_SIZE}s", name_data)[0].partition(b'\0')[0].decode('utf-8'))
            offset += NAME_SIZE

            key_data = payload[offset:offset + PUBLIC_KEY_SIZE]
            self.public_key = struct.unpack(f"<{PUBLIC_KEY_SIZE}s", key_data)[0]
            return True
        except:
            self.name = DEFAULT_STR
            self.public_key = DEFAULT_STR
            return False


class LoginRequest(RegistrationRequest):
    def __init__(self):
        # the payload of the two requests are the same so no point in copying code...
        super().__init__()


class FileSendRequest:

    def __init__(self):
        self.header = RequestHeader()
        self.content_size = DEFAULT
        self.file_name = DEFAULT_STR
        self.content = []

    def unpack(self, conn, payload):
        packet_size = len(payload)
        if not self.header.unpack(payload):
            return False

        try:
            offset = REQUEST_HEADER_SIZE
            content_size_data = payload[offset:offset + CONTENT_SIZE_SIZE]
            self.content_size = struct.unpack(f"<L", content_size_data)[0]
            offset += CONTENT_SIZE_SIZE

            file_name_data = payload[offset:offset + NAME_SIZE]
            self.file_name = struct.unpack(f"<{NAME_SIZE}s", file_name_data)[0].partition(b'\0')[0].decode('utf-8')
            offset += NAME_SIZE

            bytes_read = min(REQUEST_HEADER_SIZE + self.header.payload_size - offset, self.content_size)
            # because the size of message content varies, as long as we have more content to read we'll do so
            self.content.append(struct.unpack(f"<{bytes_read}s", payload[offset:offset + bytes_read])[0])
            while bytes_read < self.content_size:
                data = conn.recv(packet_size)
                data_size = len(data)
                # because we know the content size,
                # we can make sure the server won't read any spam by limiting data_size to content size - bytes read
                data_size = min(data_size, self.content_size - bytes_read)
                self.content.append(struct.unpack(f"<{data_size}s", data[:data_size])[0])
                bytes_read += data_size
            return True
        except Exception as e:
            print(f"Exception while unpacking file request - {e}")
            self.content_size = DEFAULT
            self.file_name = DEFAULT_STR
            self.content = []
            return False


class CRCRequest:
    def __init__(self):
        self.header = RequestHeader()
        self.file_name = DEFAULT_STR

    def unpack(self, payload):
        if not self.header.unpack(payload):
            return False
        try:
            name_data = payload[REQUEST_HEADER_SIZE:REQUEST_HEADER_SIZE + NAME_SIZE]
            self.file_name = str(struct.unpack(f"<{NAME_SIZE}s", name_data)[0].partition(b'\0')[0].decode('utf-8'))
            return True
        except:
            self.file_name = DEFAULT_STR
            return False


# all 3 CRC requests are handled the same.
# valid is if the value is equal
# warning is for the first 3 times that value is different
# error is for the forth time meaning failed sending

class ValidCRCRequest(CRCRequest):
    pass


class WarningCRCRequest(CRCRequest):
    pass


class ErrorCRCRequest(CRCRequest):
    pass


"""
==================

    RESPONSES

==================
"""


class GenericResponse:  # 2104
    def __init__(self):
        self.header = ResponseHeader(ResponseCodes.RESPONSE_RECEIVED.value)
        self.client_id = DEFAULT_STR

    def pack(self):
        try:
            data = self.header.pack()
            data += struct.pack(f"<{CLIENT_ID_SIZE}s", self.client_id)
            return data
        except Exception as e:
            print(f"Error when packing: {e}")
            return DEFAULT_STR


class RegistrationResponse(GenericResponse):  # 2100
    def __init__(self):
        super().__init__()
        self.header = ResponseHeader(ResponseCodes.RESPONSE_REGISTRATION.value)


class RegistrationFailedResponse:  # 2101
    def __init__(self):
        self.header = ResponseHeader(ResponseCodes.RESPONSE_FAILED_REGISTRATION.value)

    def pack(self):
        try:
            return self.header.pack()
        except:
            return DEFAULT_STR


class PublicKeyResponse:  # 2102
    def __init__(self):
        self.header = ResponseHeader(ResponseCodes.RESPONSE_PUBLIC_KEY.value)
        self.client_id = DEFAULT_STR
        self.symmetric_key = DEFAULT_STR

    def pack(self):
        try:
            data = self.header.pack()
            data += struct.pack(f"<{CLIENT_ID_SIZE}s", self.client_id)
            data += struct.pack(f"<{self.header.payload_size - CLIENT_ID_SIZE}s", self.symmetric_key)
            return data
        except:
            return DEFAULT_STR


class CRCResponse:  # 2103
    def __init__(self):
        self.header = ResponseHeader(ResponseCodes.RESPONSE_FILE.value)
        self.client_id = DEFAULT_STR
        self.content_size = DEFAULT
        self.file_name = DEFAULT_STR
        self.cksum = DEFAULT_STR

    def pack(self):
        try:
            data = self.header.pack()
            data += struct.pack(f"<{CLIENT_ID_SIZE}s", self.client_id)
            data += struct.pack(f"<L", self.content_size)
            data += struct.pack(f"<{NAME_SIZE}s", self.file_name)
            data += struct.pack(f"<L", self.cksum)
            return data
        except Exception as e:
            print(f"Exception while packing CRC - {e}")
            return DEFAULT_STR


class LoginResponse(PublicKeyResponse):  # 2105
    def __init__(self):
        super().__init__()
        # override the code
        self.header = ResponseHeader(ResponseCodes.RESPONSE_LOGIN.value)


class LoginFailedResponse(GenericResponse):  # 2106
    def __init__(self):
        super().__init__()
        self.header = ResponseHeader(ResponseCodes.RESPONSE_FAILED_LOGIN.value)


class ErrorResponse:
    def __init__(self):
        self.header = ResponseHeader(ResponseCodes.RESPONSE_ERROR.value)

    def pack(self):
        try:
            return self.header.pack()
        except:
            return DEFAULT_STR
