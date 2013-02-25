#! /usr/bin/env python

# An HTTP Proxy to assist in detecting unwanted injected code

import sys
import argparse
import random
from twisted.web import proxy, http
from twisted.internet import reactor
from twisted.python import log


whitelist = set()
landing_urls = list()

def main():

    args = process_args()

    for line in args.test_url_file:
        landing_urls.append(line.rstrip())
        whitelist.add(line.rstrip()) # test urls are implicitly in the whitelist

    if args.whitelist_file is not None:
        for line in args.whitelist_file:
            whitelist.add(line.rstrip())

    pfactory = ProxyFactory()
    reactor.listenTCP(8080, pfactory)
    reactor.run()


def process_args():

    parser = argparse.ArgumentParser(description='Detect unwanted redirects on a website', prog='InjectDetect')

    parser.add_argument('-f', '--test-url-file', type=argparse.FileType('r'), required=True, help='File with urls to redirect the browser to')
    parser.add_argument('-w', '--whitelist-file', type=argparse.FileType('r'), help='Whitelisted urls that are allowed through the proxy')

    return parser.parse_args()


def allowed_url(url):
    """Check to see if the given url is in the list of whitelist urls"""
    global whitelist

    param_pos = url.find('?')
    if param_pos != -1:
        url = url[:param_pos]

    if url in whitelist:
        return True

    return False

def get_redirect():
    global landing_urls 

    return random.choice(landing_urls)


class InjectDetectProxy(proxy.Proxy):
    def dataReceived(self, data):

        first = data.split('\r\n',1)
        parts = data.split(' ')
        url = parts[1]

        # Redirect requests from google search to one of our urls
        # Simulating clicking through a search
        if url.find('http://www.google.com/search') == 0:
            new_url = get_redirect()
            print "Redirecting to: %s" % new_url
            self.transport.write("HTTP/1.1 200 OK\r\n")
            self.transport.write("Refresh: 0; url=%s\r\n\r\n" % new_url)
            self.transport.loseConnection()

        # Log bad urls
        elif not allowed_url(url):
            print "Non whitelisted url requested: %s" % url
            self.transport.write("HTTP/1.1 503 Service Unavailable\r\n\r\n")
            self.transport.loseConnection()
            return

        # Proxy everything else
        else:
            return proxy.Proxy.dataReceived(self, data)

class ProxyFactory(http.HTTPFactory):
    protocol = InjectDetectProxy


main()
