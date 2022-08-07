import os
import logging
from datetime import datetime, timezone
import socketserver
import http.server
import urllib.error
from urllib.request import urlopen, Request

import uuid
import jwt
import redis


REDIS_HOST = os.environ["REDIS_HOST"]
REDIS_PORT = os.environ["REDIS_PORT"]
HTTP_PORT = 9098
SECRET = os.environ["SECRET"]

start_time = datetime.now()  # server start time
requests_processed = 0  # expected to store number of POST requests processed since server started


def encode_jwt(username: str, date: datetime):
    """
    function for encoding a unique JWT with ait, jti and payload claims
    :param username: str username for user identification
    :param date: datetime object
    :return: HS512 encoded JWT
    """
    nonce = JTINonceGenerator.generate()  # generates unique nonce
    claims = {
        "iat": datetime.now(tz=timezone.utc),
        "jti": nonce,
        "payload": {
            "user": username,
            "date": date.isoformat()
        }
    }
    token = jwt.encode(claims, key=SECRET, algorithm="HS512")  # encodes claims with HS512 Algorithm using secret key
    return token


class JTINonceGenerator:
    """
    JTINonceGenerator is a class for the generation ond management of unique nonce tokens to be used in the jti claim
    """
    # class maintains a connection to a redis instance for the storage of blacklisted jtis, redis is used in case
    # multiple instances of the proxy server is started up
    __redis = redis.Redis(host=REDIS_HOST, port=REDIS_PORT)

    @classmethod
    def __blacklist(cls, token: str):
        """
        adds token to blacklist
        :param token: unique string value
        """
        cls.__redis.set(token, 1)

    @classmethod
    def __blacklisted(cls, token) -> bool:
        """
        checks if token has been blacklisted
        :param token: string value
        :return: boolean true if token has been blacklisted, else false
        """
        return cls.__redis.get(token) is not None

    @classmethod
    def generate(cls):
        """
        uses the uuid module to generate a UUIDv4 token, the resulting token is blacklisted if it hasn't been
        blacklisted before. This function will keep generating a token till uniqueness is guaranteed.
        :return: a unique UUIDv4 token
        """
        nonce = uuid.uuid4().__str__()
        while cls.__blacklisted(nonce):
            nonce = uuid.uuid4().__str__()
        cls.__blacklist(nonce)
        return nonce


class Proxy(http.server.SimpleHTTPRequestHandler):
    """Proxy class"""

    def serve_status_page(self):
        """
        function responsible for serving the /status page.
        the page reveals dynamic html content
        Time Since Server Start: (time now - time since server start) in seconds
        POST requests processed: number of post requests processed
        """
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.end_headers()
        html = f"""<!doctype html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport"
          content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <title>Proxy Status</title>
</head>
<body>
    <h2>Time Since Server Start: {(datetime.now() - start_time).seconds} seconds</h2>
    <h2>POST requests processed: {requests_processed}</h2>
</body>
</html>
        """
        self.wfile.write(bytes(html, "utf8"))
        return

    def do_GET(self) -> None:
        """
        GET request handler
        The proxy makes get requests to an upstream server on behalf of the user
        navigating to http://localhost:9098/https:google.com will display th Google home page through the proxy
        """
        if self.path == "/status":  # displays status page at http://localhost:9098/status/
            self.serve_status_page()
        else:
            url = self.path[1:]  # path of upstream server
            try:
                output = urlopen(url)  # makes get request
            except urllib.error.HTTPError as e:
                # in case of an HTTP error, the response is forwarded to the user
                self.send_response(e.code)
                self.end_headers()
                self.copyfile(e, self.wfile)
                logging.info("error: http error from url -", url)
            except urllib.error.URLError:
                # in case of a connection error, the user receives a 500 error
                self.send_response(500)
                self.end_headers()
                logging.info("error: could not open url -", url)
            else:
                # if the request to the upstream server was successful, pass the response back to the user
                self.send_response(200)
                self.end_headers()
                self.copyfile(output, self.wfile)

    def do_POST(self):
        """
        POST request handler
        Setting the proxy of your http client to http://localhost:9098/ enables you to make proxied POST requests
        """
        global requests_processed

        url = self.path
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length:
            # grab the content of the body of the incoming request if it exists
            content = self.rfile.read(content_length)
        else:
            content = None

        # get headers of incoming request and append x-my-jwt
        headers = {**dict(self.headers.items()), "x-my-jwt": encode_jwt("username", datetime.now())}
        req = Request(url, method="POST", data=content, headers=headers)  # build request to upstream server
        try:
            output = urlopen(req)
        except urllib.error.HTTPError as e:
            # in case of an HTTP error, the response is forwarded to the user
            self.send_response(e.code)
            self.end_headers()
            self.copyfile(e, self.wfile)
            logging.info("error: http error from url -", url)
        except urllib.error.URLError:
            # in case of a connection error, the user receives a 503 error
            self.send_response(503)
            self.end_headers()
            logging.info("error: could not open url -", url)
        else:
            # if the request to the upstream server was successful, pass the response back to the user
            self.send_response(200)
            self.end_headers()
            self.copyfile(output, self.wfile)
        finally:
            # increment number of POST requests processed
            requests_processed += 1


if __name__ == "__main__":  # main procedure
    httpd = None
    try:
        socketserver.TCPServer.allow_reuse_address = True
        httpd = socketserver.TCPServer(("0.0.0.0", HTTP_PORT), Proxy)  # bind server to 0.0.0.0:$HTTP_PORT
        print(f"proxy running at port: {HTTP_PORT}")
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("shutdown proxy server")
    finally:
        if httpd:
            httpd.shutdown()  # clean shutdown of server
