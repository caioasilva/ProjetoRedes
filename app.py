from pathlib import Path


class HTTPServer:
    def __init__(self, filesDir="www"):
        self.filesDir = filesDir

    def request(self, data):
        if data[-4:] == b'\r\n\r\n':
            try:
                method, path, http = data.split(b' ', 2)
                if method == b'GET':
                    path = path.decode()
                    print("GET", path)
                    if path == "/":
                        path = "/index.html"
                    file = Path(self.filesDir + path)
                    if file.is_file():
                        bin = file.read_bytes()
                        header = b"HTTP/1.0 200 OK\r\nContent-Length: %d\r\n\r\n" % len(bin)
                        resp = header + bin
                        print("200 OK")
                    else:
                        bin = b"File not found"
                        header = b"HTTP/1.0 404 Not Found\r\nContent-Length: %d\r\n\r\n" % len(bin)
                        resp = header + bin
                        print("404 Not Found")
                else:
                    # other methods not implemented
                    resp = self.badRequest()
                return resp
            except Exception as e:
                print(e)
                return self.badRequest()
        else:
            return self.badRequest()

    @staticmethod
    def badRequest():
        bin = b"Bad Request"
        header = b"HTTP/1.0 400 Bad Request\r\nContent-Length: %d\r\n\r\n" % len(bin)
        resp = header + bin
        print("400 Bad Request")
        return resp
