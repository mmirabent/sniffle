import socket

# List of the top 25 sites according to Alexa
websites = [ "Google.com",
             "Facebook.com",
             "Youtube.com",
             "Baidu.com",
             "Yahoo.com",
             "Amazon.com",
             "Wikipedia.org",
             "Qq.com",
             "Twitter.com",
             "Google.co.in",
             "Taobao.com",
             "Live.com",
             "Sina.com.cn",
             "Linkedin.com",
             "Yahoo.co.jp",
             "Weibo.com",
             "Ebay.com",
             "Google.co.jp",
             "Yandex.ru",
             "Blogspot.com",
             "Vk.com",
             "Hao123.com",
             "T.co",
             "Bing.com",
             "Google.de"]

ip_addresses = []

# Open a bunch of TCP connections on port 80 and close them. Wait at most 1 sec
# before timing out. Timing out raises a socket.timeout exception. Catch it and
# proceed.
for site in websites:
    try:
        sock = socket.create_connection((site, 80),1)
        sock.close()
    except socket.timeout:
        pass

