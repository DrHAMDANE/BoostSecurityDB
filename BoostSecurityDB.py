#!/usr/bin/env python
# -*- coding:utf-8 -*-
# -----------------------------------------
# 
# 
# -----------------------------------------

from tkinter import *
import os
import re
import sys
import lib.core.convert
import codecs
import random
import time
import socket
import threading
import subprocess


from lib.core.option2 import setPaths
from lib.core.option2 import getFileItems
from lib.core.option2 import getPublicTypeMembers
from lib.core.option2 import paths
from lib.core.option2 import InjectionDict
from lib.core.option2 import AttribDict
from lib.core.option2 import logger
from lib.core.option2 import setupTargetEnv
from lib.core.option3 import REFLECTIVE_COUNTER
from lib.core.option3 import HTTPMETHOD
from lib.core.option3  import PLACE
from lib.core.option3  import PAYLOAD
from lib.core.option3 import CONTENT_TYPE
from lib.core.defaults import defaults
from lib.core.datatype import OrderedSet
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import queries
from lib.core.agen import agent 
from lib.controller.handle import setHandler 
from lib.parse.cmdlinee import cmdLineParser 
from lib.core import option4
from thirdparty.six.moves import urllib as _urllib
from thirdparty.six.moves import collections_abc as _collections
from xml.etree.ElementTree import ElementTree

UNICODE_ENCODING = "utf8"
cmdLineOptions = AttribDict()

def logoBoostSecurity():
    print(r"                       _______                                      ")
    print(r"                      |  __   |                  _     -----                                    _      ")
    print(r"                      | |__|  |                 | |_  /     |                                  | |_           ")
    print(r"                      | ____ /  ___   ___   ___ |  _||  ---     ___    ____  _    _  _ ____  _ |  _|   _    _    ")
    print(r"                     |  __  \ / _ \ / _ \ / __|| |   \__   \  / || \ / ___|| |  | || ____|| ||| |     | |  | |      ")
    print(r"                      | |__|  | |_| | |_| |\__ \| |__| ___   || ___ /| |___ | |__| || |     | || |__  | |__| |    ")
    print(r"                      |_______|\___/ \___/ |___/|____||___ /   \___   \____||______||_|     |_||____| |______|        ")
    print(r"                                                                                                             |      ")
    print(r"                                                                                                       ______|   ") 
    print(r"                                                    _____    _______          ")
    print(r"                                                   |     \  |  __   |     ")
    print(r"                                                   |  _   \ | |__|  |      ")
    print(r"                                                   | | |   || ____ /      ")
    print(r"                                                   | |_|   ||  __  \         ")
    print(r"                                                   |      / | |__|  |    ")
    print(r"                                                   |_____/  |_______|        ")
    
    
def getConsoleWidth(default=80):
    """
    Returns console width
    >>> any((getConsoleWidth(), True))
    True
    """
    width = None
    if os.getenv("COLUMNS", "").isdigit():
        width = int(os.getenv("COLUMNS"))
    else:
       output = shellExec("stty size")
       match = re.search(r"\A\d+ (\d+)", output)   
    return width or default

def shellExec(cmd):
    """
    Executes arbitrary shell command

    >>> shellExec('echo 1').strip() == '1'
    True
    """
    retVal = ""

    return retVal


def update():
   pass
def _setKnowledgeBaseAttributes(flushAll=True):
    """
    This function set some needed attributes into the knowledge base
    singleton.
    """
    kb.authHeader = None      
    kb.browserVerification = None
    kb.brute = AttribDict({"tables": [], "columns": []})
    kb.bruteMode = False   
    kb.captchaDetected = None
    kb.counters = {}
    kb.data = AttribDict() 
    # Active back-end DBMS fingerprint
    kb.dbms = None
    kb.dbmsFilter = []        
    kb.disableHtmlDecoding = False
    kb.dnsMode = False          
    kb.extendTests = None
    kb.errorChunkLength = None
    kb.errorIsNone = True   
    kb.fileReadMode = False 
    kb.forceWhere = None          
    kb.headersFile = None  
    kb.heuristicExtendedDbms = None
    kb.heuristicMode = False     
    kb.inferenceMode = False   
    kb.ignoreTimeout = False    
    kb.injection = InjectionDict()
    kb.injections = []    
    kb.locks = AttribDict()
    for _ in ("cache", "connError", "count", "handlers", "hint", "index", "io", "limit", "liveCookies", "log", "socket", "redirect", "request", "value"):
        kb.locks[_] = threading.Lock()        
    kb.mergeCookies = None
    kb.multiThreadMode = False
    kb.nullConnection = None        
    kb.originalCode = None
    kb.originalPage = None       
    kb.originalUrls = dict()
    # Back-end DBMS underlying operating system fingerprint via banner (-b)
    # parsing    
    kb.pageCompress = True           
    kb.postHint = None    
    kb.postUrlEncode = True   
    kb.processResponseCounter = 0
    kb.processUserMarks = None
   
    kb.reflectiveCounters = {REFLECTIVE_COUNTER.MISS: 0, REFLECTIVE_COUNTER.HIT: 0}
    kb.requestCounter = 0   
    kb.resolutionDbms = None
    kb.responseTimes = {}
    kb.responseTimeMode = None    
    kb.resumeValues = True        
    kb.secondReq = None
    kb.serverHeader = None
    
    kb.testQueryCount = 0           
    kb.unionDuplicates = False  
    if flushAll:      
        kb.keywords = set(getFileItems(paths.SQL_KEYWORDS))          
        kb.postprocessFunctions = []
        kb.preprocessFunctions = []       
        kb.storeCrawlingChoice = None        
        kb.targets = OrderedSet()      
        kb.userAgents = None     
        kb.vulnHosts = set()       
        kb.wordlists = None


def initOptions(inputOptions=AttribDict(), overrideOptions=False):
   
    conf.httpHeaders = []        
    conf.multipleTargets = False   
    conf.paramDict = {}
    conf.parameters = {}
    _setKnowledgeBaseAttributes()
    if hasattr(inputOptions, "items"):
        inputOptionsItems = inputOptions.items()
    for key, value in inputOptionsItems:
        if key not in conf or value not in (None, False) or overrideOptions:
            conf[key] = value
    for key, value in defaults.items():
        if hasattr(conf, key) and conf[key] is None:
            conf[key] = value             
    lut = {}

def _selectInjection():
    """
    Selection function for injection place, parameters and type.
    """
    points = {}
    for injection in kb.injections:
        place = injection.place
        parameter = injection.parameter
        ptype = injection.ptype
        point = (place, parameter, ptype)
        if point not in points:
            points[point] = injection
        
    if len(points) == 1:
        kb.injection = kb.injections[0]
    elif len(points) > 1:
        message += "the one to use for following injections:\n"
        points = []     
        kb.injection = kb.injections[index]

def _formatInjection(inj):
    paramType = conf.method if conf.method not in (None, HTTPMETHOD.GET, HTTPMETHOD.POST) else inj.place
    data = "Parameter: %s (%s)\n" % (inj.parameter, paramType)
    for stype, sdata in inj.data.items():
        title = sdata.title
        vector = sdata.vector
        comment = sdata.comment
       
        if inj.place == PLACE.CUSTOM_HEADER:
            payload = payload.split(',', 1)[1]
        if stype == PAYLOAD.TECHNIQUE.UNION:
            count = re.sub(r"(?i)(\(.+\))|(\blimit[^a-z]+)", "", sdata.payload).count(',') + 1
            title = re.sub(r"\d+ to \d+", str(count), title)
            vector = agent.forgeUnionQuery("[QUERY]", vector[0], vector[1], vector[2], None, None, vector[5], vector[6])
            if count == 1:
                title = title.replace("columns", "column")
        elif comment:
            vector = "%s%s" % (vector, comment)
        data += "    Type: %s\n" % PAYLOAD.SQLINJECTION[stype]
        data += "    Title: %s\n" % title
        data += "    Vector: %s\n\n" % vector if conf.verbose > 1 else "\n"
    return data

def _showInjections():
    if conf.wizard and kb.wizardMode:
        kb.wizardMode = False
    if kb.testQueryCount > 0:
        header = "BoostSecurity identified the following injection point(s) with "
        header += "a total of %d HTTP(s) requests" % kb.testQueryCount
    else:
        header = "BoostSecurity resumed the following injection point(s) from stored session"
    
    data = "".join(set(_formatInjection(_) for _ in kb.injections)).rstrip("\n")
    conf.dumper.string(header, data)

def action():
    """
    This function exploit the SQL injection on the affected
    URL parameter and extract requested data from the
    back-end database management system or operating system
    if possible
    """
    # First of all we have to identify the back-end database management
    # system to be able to go ahead with the injection
    setHandler()
    # Enumeration options
    if conf.getDbs:
        try:
            conf.dumper.dbs(conf.dbmsHandler.getDbs())       
        except:
            pass
    if conf.getTables:
        try:
            conf.dumper.dbTables(conf.dbmsHandler.getTables())
        except:
            pass
    if conf.getColumns:
        try:
            conf.dumper.dbTableColumns(conf.dbmsHandler.getColumns(), CONTENT_TYPE.COLUMNS)
        except:
            pass

def start():
    """
    This function calls a function that performs checks on both URL
    stability and all GET, POST, Cookie and User-Agent parameters to
    check if they are dynamic and SQL injection affected
    """
    if conf.url and not any((conf.forms, conf.crawlDepth)):
        kb.targets.add((conf.url, conf.method, conf.data, conf.cookie, None))
    targetCount = 0
    initialHeaders = list(conf.httpHeaders)
    for targetUrl, targetMethod, targetData, targetCookie, targetHeaders in kb.targets:
        targetCount += 1
        try:          
            parseTargetUrl()                          
            setupTargetEnv()
            if len(kb.injections) == 0 or (len(kb.injections) == 1 and kb.injections[0].place is None):
                if kb.vainRun and not conf.multipleTargets:
                    errMsg = "no parameter(s) found for testing in the provided data "
                    errMsg += "(e.g. GET parameter 'id' in 'www.site.com/index.php?id=1')" 
                else:
                    errMsg = "all tested parameters do not appear to be injectable."
            else:
                _showInjections()
                _selectInjection()
            if kb.injection.place is not None and kb.injection.parameter is not None:
               
                    action()
        except KeyboardInterrupt:
           pass            
    return True





def _loadQueries():
    """
    Loads queries from 'xml/queries.xml' file.
    """
    def iterate(node, retVal=None):
        class DictObject(object):
            def __init__(self):
                pass

            def __contains__(self, name):
               pass

        if retVal is None:
            retVal = DictObject()
        for child in node.findall("*"):
            instance = DictObject()
            retVal.__dict__[child.tag] = instance
            if child.attrib:
                instance.__dict__.update(child.attrib)
            else:
                iterate(child, instance)
        return retVal
    tree = ElementTree()
    tree.parse(paths.QUERIES_XML)   
    for node in tree.findall("*"):
        queries[node.attrib['value']] = iterate(node)


def _setTechnique():
    validTechniques = sorted(getPublicTypeMembers(PAYLOAD.TECHNIQUE), key=lambda x: x[1])
    validLetters = [_[0][0].upper() for _ in validTechniques]
   
    if conf.technique and isinstance(conf.technique, option4.string_types):
        conf.technique = []

def _cleanupOptions():
    """
    Cleanup configuration attributes.
    """
    if conf.encoding:
        try:
            codecs.lookup(conf.encoding)
        except LookupError:
            errMsg = "unknown encoding '%s'" % conf.encoding
    debugMsg = "cleaning up configuration parameters"
    logger.debug(debugMsg)
    width = getConsoleWidth()
    for key, value in conf.items():
        if value and any(key.endswith(_) for _ in ("Path", "File", "Dir")):
            if isinstance(value, str):
                conf[key] = safeExpandUser(value)
    
    conf.base64Parameter = []



def init():
    """
    Set attributes into both configuration and knowledge base singletons
    based upon command line and configuration file options.
    """
    _cleanupOptions()
    if any((conf.url, conf.logFile, conf.bulkFile, conf.requestFile, conf.googleDork, conf.stdinPipe)):   
        _setTechnique()    
    _loadQueries()


def filterrNone(values):

    retVal = values

    if isinstance(values, _collections.Iterable):
        retVal = [_ for _ in values if _]

    return retVal


def resolveCrossReferences():
    """
    Place for cross-reference resolution
    """

    lib.core.convert.filterNone = filterrNone   

def getUnicode(value, encoding=None, noneToNull=False):
    """
    Returns the unicode representation of the supplied value

    >>> getUnicode('test') == u'test'
    True
    >>> getUnicode(1) == u'1'
    True
    >>> getUnicode(None) == 'None'
    True
    """

    if noneToNull and value is None:
        return NULL

    if isinstance(value, option4.text_type):
        return value
    elif isinstance(value, option4.binary_type):
        # Heuristics (if encoding not explicitly specified)
        candidates = filterNone((encoding, kb.get("pageEncoding") if kb.get("originalPage") else None, conf.get("encoding"), UNICODE_ENCODING, sys.getfilesystemencoding()))
        if all(_ in value for _ in (b'<', b'>')):
            pass
        elif any(_ in value for _ in (b":\\", b'/', b'.')) and b'\n' not in value:
            candidates = filterNone((encoding, sys.getfilesystemencoding(), kb.get("pageEncoding") if kb.get("originalPage") else None, UNICODE_ENCODING, conf.get("encoding")))
        

  
    else:
        try:
            return option4.text_type(value)
        except UnicodeDecodeError:
            return option4.text_type(str(value), errors="ignore")  
def parseTargetUrl():
    """
    Parse target URL and set some attributes into the configuration singleton

    >>> pushValue(conf.url)
    >>> conf.url = "https://www.test.com/?id=1"
    >>> parseTargetUrl()
    >>> conf.hostname
    'www.test.com'
    >>> conf.scheme
    'https'
    >>> conf.url = popValue()
    """
    originalUrl = conf.url  
    urlSplit = _urllib.parse.urlsplit(conf.url)
    hostnamePort = urlSplit.netloc.split(":") if not re.search(r"\[.+\]", urlSplit.netloc) else filterNone((re.search(r"\[.+\]", urlSplit.netloc).group(0), re.search(r"\](:(?P<port>\d+))?", urlSplit.netloc).group("port")))
    conf.scheme = (urlSplit.scheme.strip().lower() or "http")
    conf.path = urlSplit.path.strip()
    conf.hostname = hostnamePort[0].strip()
 
    
    if len(hostnamePort) == 2:
        conf.port = int(hostnamePort[1])
    else:
        conf.port = 80 
    conf.url = getUnicode("%s://%s:%d%s" % (conf.scheme, ("[%s]" % conf.hostname) if conf.ipv6 else conf.hostname, conf.port, conf.path))
    if urlSplit.query:
        if '=' not in urlSplit.query:
            conf.url = "%s?%s" % (conf.url, getUnicode(urlSplit.query))
        else:
            conf.parameters[PLACE.GET] = urlSplit.query

def modulePath():
    """
    This will get us the program's directory, even if we are frozen
    using py2exe
    """
    _ = __file__
    return getUnicode(os.path.dirname(os.path.realpath(_)))

def main():
    
    print("                       _______                                      ")
    print("                      |  __   |                  _     -----                                    _      ")
    print("                      | |__)  |                 | |_  /     |                               <> | |_           ")
    print("                      | ____ /  ___   ___   ___ |  _||  ---     ___    ____  _    _  _ ____  _ |  _|   _    _    ")
    print("                      |  __  \ / _ \ / _ \ / __|| |   \__   \  / |> \ / ___|| |  | || `____|| || |    | |  | |      ")
    print("                      | |__)  | |_| | |_| |\__ \| |__| ___   || ___ /| |___ | |__| || |     | || |__  | |__| |    ")
    print("                      |_______|\___/ \___/ |___/|____||___ /   \___   \____||______||_|     |_||____| |______|        ")
    print("                                                                                                             |      ")
    print("                                                                                                       ______|   ") 
    print("                                                    _____    _______          ")
    print("                                                   |     \  |  __   |     ")
    print("                                                   |  _   \ | |__)  |      ")
    print("                                                   | | |   || ____ /      ")
    print("                                                   | |_|   ||  __  \         ")
    print("                                                   |      / | |__)  |    ")
    print("                                                   |_____/  |_______|        ")
    
    try:       
        resolveCrossReferences()
        setPaths(modulePath())
        
        # Store original command line options for possible later restoration
        args = cmdLineParser()
        cmdLineOptions.update(args.__dict__ if hasattr(args, "__dict__") else args)
        initOptions(cmdLineOptions)       
        init()
        start()       
    except SystemExit as ex:
        os._exitcode = ex.code or 0

def function_sqlmap():
  
 
  
  if __name__ == "__main__":
    try:
        main()
    finally:
            sys.exit(getattr(os, "_exitcode", 0))     

def myfunction():
   pass

def vuln():
 
 import sys
 import argparse
 import subprocess
 import os
 import time
 import random
 import threading
 import re
 import random
 from urllib.parse import urlsplit

 logoBoostSecurity()
 CURSOR_UP_ONE = '\x1b[1A' 
 ERASE_LINE = '\x1b[2K'

# Scan Time Elapser
 intervals = (
    ('h', 3600),
    ('m', 60),
    ('s', 1),
     )
 def display_time(seconds, granularity=3):
    result = []
    seconds = seconds + 1
    for name, count in intervals:
        value = seconds // count
        if value:
            seconds -= value * count
            result.append("{}{}".format(value, name))
    return ' '.join(result[:granularity])


 def terminal_size():
    try:
        rows, columns = subprocess.check_output(['stty', 'size']).split()
        return int(columns)
    except subprocess.CalledProcessError as e:
        return int(20)
    


 def url_maker(url):
    if not re.match(r'http(s?)\:', url):
        url = 'http://' + url
    parsed = urlsplit(url)
    host = parsed.netloc
    if host.startswith('www.'):
        host = host[4:]
    return host

 def check_internet():
    os.system('ping -c1 github.com > rs_net 2>&1')
    if "0% packet loss" in open('rs_net').read():
        val = 1
    else:
        val = 0
    os.system('rm rs_net > /dev/null 2>&1')
    return val


# Initializing the color module class
 class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    BADFAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    BG_ERR_TXT  = '\033[41m' 
    BG_HEAD_TXT = '\033[100m'
    BG_ENDL_TXT = '\033[46m'
    BG_CRIT_TXT = '\033[45m'
    BG_HIGH_TXT = '\033[41m'
    BG_MED_TXT  = '\033[43m'
    BG_LOW_TXT  = '\033[44m'
    BG_INFO_TXT = '\033[42m'

    BG_SCAN_TXT_START = '\x1b[6;30;42m'
    BG_SCAN_TXT_END   = '\x1b[0m'


# Classifies the Vulnerability's Severity
 def vul_info(val):
    result =''
    if val == 'c':
        result = bcolors.BG_CRIT_TXT+" critical "+bcolors.ENDC
    elif val == 'h':
        result = bcolors.BG_HIGH_TXT+" high "+bcolors.ENDC
    elif val == 'm':
        result = bcolors.BG_MED_TXT+" medium "+bcolors.ENDC
    elif val == 'l':
        result = bcolors.BG_LOW_TXT+" low "+bcolors.ENDC
    else:
        result = bcolors.BG_INFO_TXT+" info "+bcolors.ENDC
    return result

# Legends
 proc_high = bcolors.BADFAIL + "●" + bcolors.ENDC
 proc_med  = bcolors.WARNING + "●" + bcolors.ENDC
 proc_low  = bcolors.OKGREEN + "●" + bcolors.ENDC



# Initiliazing the idle loader/spinner class
 class Spinner:
    busy = False
    delay = 0.005 # 0.05

    @staticmethod
    def spinning_cursor():
        while 1:
            
            for cursor in ' ': yield cursor
    def __init__(self, delay=None):
        self.spinner_generator = self.spinning_cursor()
        if delay and float(delay): self.delay = delay
        self.disabled = False

    def spinner_task(self):
        inc = 0
        try:
            while self.busy:
                if not self.disabled:
                    
                    inc = inc + 1
                    
                    if inc>random.uniform(0,terminal_size()): #30 init
                        print(end="\r")
                        bcolors.BG_SCAN_TXT_START = '\x1b[6;30;'+str(round(random.uniform(40,47)))+'m'
                        inc = 0
                    sys.stdout.flush()
                time.sleep(self.delay)
                if not self.disabled:
                    sys.stdout.flush()

        except (KeyboardInterrupt, SystemExit):
            print("\n\t"+ bcolors.BG_ERR_TXT+"RapidScan received a series of Ctrl+C hits. Quitting..." +bcolors.ENDC)
            sys.exit(1)

    def start(self):
        self.busy = True
        try:
            threading.Thread(target=self.spinner_task).start()
        except Exception as e:
            print("\n")
        
    def stop(self):
        try:
            self.busy = False
            time.sleep(self.delay)
        except (KeyboardInterrupt, SystemExit):
            print("\n\t"+ bcolors.BG_ERR_TXT+"RapidScan received a series of Ctrl+C hits. Quitting..." +bcolors.ENDC)
            sys.exit(1)



# Instantiating the spinner/loader class
 spinner = Spinner()



# Scanners that will be used and filename rotation (default: enabled (1))
 tool_names = [

                ["nmap","Nmap - Fast Scan [Only Few Port Checks]","nmap",1],

                ["nmap_sqlserver","Nmap - Checks for MS-SQL Server DB","nmap",1],
                ["nmap","Nmap - Fast Scan [Only Few Port Checks]","nmap",1],
                ["nmap_mysql", "Nmap - Checks for MySQL DB","nmap",1],

                ["nmap_oracle", "Nmap - Checks for ORACLE DB","nmap",1],
                ["nmap_stuxnet","Nmap [STUXNET] - Checks if the host is affected by STUXNET Worm.","nmap",1],
                ["nikto_paths","Nikto - Checks for Injectable Paths.","nikto",1],

            ]


# Command that is used to initiate the tool (with parameters and extra params)
 tool_cmd   = [
                #1
                ["host ",""],

                #2
                ["wget -O /tmp/rapidscan_temp_aspnet_config_err --tries=1 ","/%7C~.aspx"],

              
                #8
                ["nmap -F --open -Pn ",""],

                #9
                ["theHarvester -l 50 -b google -d ",""],

                #10
                ["dnsrecon -d ",""],

               

            
                #18
                ["nmap -p443 --script ssl-poodle -Pn ",""],

                #19
                ["nmap -p443 --script ssl-ccs-injection -Pn ",""],

          

                #35
                ["golismero -e zone_transfer scan ",""],


                #42
                ["nmap -p23 --open -Pn ",""],

                #43
            
                #50
                ["uniscan -s -u ",""],

                ["nikto -Plugins 'ms10-070' -host ",""],

                #59
                ["nikto -Plugins 'msgs' -host ",""],

             

          
                
             
            ]


# Tool Responses (Begins) [Responses + Severity (c - critical | h - high | m - medium | l - low | i - informational) + Reference for Vuln Definition and Remediation]
 tool_resp   = [
               

             

                #19
                ["OpenSSL CCS Injection Detected.","h",16],

                #20
                ["FREAK Vulnerability Detected.","h",17],

                #21
                ["LOGJAM Vulnerability Detected.","h",18],

    

                #43
                ["FTP Service Detected.","c",33],

                #44
                ["Vulnerable to STUXNET.","c",34],

                #45
                ["WebDAV Enabled.","m",35],

                #46
                ["Found some information through Fingerprinting.","l",36],

           

                #71
                ["RDP Server Detected over TCP.","h",48],

                #72
                ["TCP Ports are Open","l",8],

                #73
                ["UDP Ports are Open","l",8],

                #74
                ["SNMP Service Detected.","m",49],

                #75
                ["Elmah is Configured.","m",50],

                #76
                ["SMB Ports are Open over TCP","m",51],

                #77
                ["SMB Ports are Open over UDP","m",51],

                #78
                ["Wapiti discovered a range of vulnerabilities","h",30],

                #79
                ["IIS WebDAV is Enabled","m",35],

                #80
                ["X-XSS Protection is not Present","m",12],

                #81
                ["Found Subdomains with AMass","m",31]



            ]

# Tool Status (Response Data + Response Code (if status check fails and you still got to push it + Legends + Approx Time + Tool Identification + Bad Responses)
 tool_status = [
                #1
                ["has IPv6",1,proc_low," < 15s","ipv6",["not found","has IPv6"]],

                #2
                ["Server Error",0,proc_low," < 30s","asp.netmisconf",["unable to resolve host address","Connection timed out"]],

                #3
                ["wp-login",0,proc_low," < 30s","wpcheck",["unable to resolve host address","Connection timed out"]],

                #4
                ["drupal",0,proc_low," < 30s","drupalcheck",["unable to resolve host address","Connection timed out"]],

                #5
                ["joomla",0,proc_low," < 30s","joomlacheck",["unable to resolve host address","Connection timed out"]],

                #6
                ["[+]",0,proc_low," < 40s","robotscheck",["Use of uninitialized value in unpack at"]],

                #7
                ["No WAF",0,proc_low," < 45s","wafcheck",["appears to be down"]],

                #8
                ["tcp open",0,proc_med," <  2m","nmapopen",["Failed to resolve"]],

                #9
                ["No emails found",1,proc_med," <  3m","harvester",["No hosts found","No emails found"]],

                #10
                ["[+] Zone Transfer was successful!!",0,proc_low," < 20s","dnsreconzt",["Could not resolve domain"]],

                

                #12
                ["0 errors",0,proc_low," < 35s","dnswalkzt",["!!!0 failures, 0 warnings, 3 errors."]],

                #13
                ["Admin Email:",0,proc_low," < 25s","whois",["No match for domain"]],

                #14
                ["XSS filter is disabled",0,proc_low," < 20s","nmapxssh",["Failed to resolve"]],

                #15
                ["VULNERABLE",0,proc_high," < 45m","nmapdos",["Failed to resolve"]],

                #16
                ["Server is vulnerable to Heartbleed",0,proc_low," < 40s","sslyzehb",["Could not resolve hostname"]],

                #17
                ["VULNERABLE",0,proc_low," < 30s","nmap1",["Failed to resolve"]],

                #18
                ["VULNERABLE",0,proc_low," < 35s","nmap2",["Failed to resolve"]],

                #19
                ["VULNERABLE",0,proc_low," < 35s","nmap3",["Failed to resolve"]],

                #20
                ["VULNERABLE",0,proc_low," < 30s","nmap4",["Failed to resolve"]],

                #21
                ["VULNERABLE",0,proc_low," < 35s","nmap5",["Failed to resolve"]],

                #22
                ["ERROR - OCSP response status is not successful",0,proc_low," < 25s","sslyze1",["Could not resolve hostname"]],

                #23
                ["VULNERABLE",0,proc_low," < 30s","sslyze2",["Could not resolve hostname"]],

                #24
                ["VULNERABLE",0,proc_low," < 25s","sslyze3",["Could not resolve hostname"]],

                #25
                ["VULNERABLE",0,proc_low," < 30s","sslyze4",["Could not resolve hostname"]],

                #26
                ["does NOT use Load-balancing",0,proc_med," <  4m","lbd",["NOT FOUND"]],

                #27
                ["No vulnerabilities found",1,proc_low," < 45s","golism1",["Cannot resolve domain name","No vulnerabilities found"]],

                #28
                ["No vulnerabilities found",1,proc_low," < 40s","golism2",["Cannot resolve domain name","No vulnerabilities found"]],

                #29
                ["No vulnerabilities found",1,proc_low," < 45s","golism3",["Cannot resolve domain name","No vulnerabilities found"]],

                #30
                ["No vulnerabilities found",1,proc_low," < 40s","golism4",["Cannot resolve domain name","No vulnerabilities found"]],

                #31
                ["No vulnerabilities found",1,proc_low," < 45s","golism5",["Cannot resolve domain name","No vulnerabilities found"]],

                #32
                ["FOUND: 0",1,proc_high," < 35m","dirb",["COULDNT RESOLVE HOST","FOUND: 0"]],

                #33
                ["Could not find any vulnerability!",1,proc_med," <  4m","xsser",["XSSer is not working propertly!","Could not find any vulnerability!"]],

                #34
                ["Occurrence ID",0,proc_low," < 45s","golism6",["Cannot resolve domain name"]],

                #35
                ["DNS zone transfer successful",0,proc_low," < 30s","golism7",["Cannot resolve domain name"]],

                #36
                ["Nikto found 0 vulnerabilities",1,proc_med," <  4m","golism8",["Cannot resolve domain name","Nikto found 0 vulnerabilities"]],

                #37
                ["Possible subdomain leak",0,proc_high," < 30m","golism9",["Cannot resolve domain name"]],

                #38
                ["AXFR record query failed:",1,proc_low," < 45s","dnsenumzt",["NS record query failed:","AXFR record query failed","no NS record for"]],

                #39
                ["Found 0 entries",1,proc_high," < 75m","fierce2",["Found 0 entries","is gimp"]],

                #40
                ["Found 0 E-Mail(s)",1,proc_low," < 30s","dmitry1",["Unable to locate Host IP addr","Found 0 E-Mail(s)"]],

                #41
                ["Found 0 possible subdomain(s)",1,proc_low," < 35s","dmitry2",["Unable to locate Host IP addr","Found 0 possible subdomain(s)"]],

                #42
                ["open",0,proc_low," < 15s","nmaptelnet",["Failed to resolve"]],

                #43
                ["open",0,proc_low," < 15s","nmapftp",["Failed to resolve"]],

                #44
                ["open",0,proc_low," < 20s","nmapstux",["Failed to resolve"]],

                #45
                ["SUCCEED",0,proc_low," < 30s","webdav",["is not DAV enabled or not accessible."]],

                #46
                ["No vulnerabilities found",1,proc_low," < 15s","golism10",["Cannot resolve domain name","No vulnerabilities found"]],

                #47
                ["[+]",0,proc_med," <  2m","uniscan2",["Use of uninitialized value in unpack at"]],

                #48
                ["[+]",0,proc_med," <  5m","uniscan3",["Use of uninitialized value in unpack at"]],

                #49
                ["[+]",0,proc_med," <  9m","uniscan4",["Use of uninitialized value in unpack at"]],

                #50
                ["[+]",0,proc_med," <  8m","uniscan5",["Use of uninitialized value in unpack at"]],

                #51
                ["[+]",0,proc_med," <  9m","uniscan6",["Use of uninitialized value in unpack at"]],

                #52
                ["0 item(s) reported",1,proc_low," < 35s","nikto1",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s)    tested"]],

                #53
                ["0 item(s) reported",1,proc_low," < 35s","nikto2",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #54
                ["0 item(s) reported",1,proc_low," < 35s","nikto3",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #55
                ["0 item(s) reported",1,proc_low," < 35s","nikto4",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #56
                ["0 item(s) reported",1,proc_low," < 35s","nikto5",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #57
                ["0 item(s) reported",1,proc_low," < 35s","nikto6",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #58
                ["0 item(s) reported",1,proc_low," < 35s","nikto7",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #59
                ["0 item(s) reported",1,proc_low," < 35s","nikto8",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #60
                ["0 item(s) reported",1,proc_low," < 35s","nikto9",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #61
                ["0 item(s) reported",1,proc_low," < 35s","nikto10",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #62
                ["0 item(s) reported",1,proc_low," < 35s","nikto11",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #63
                ["0 item(s) reported",1,proc_low," < 35s","nikto12",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #64
                ["0 item(s) reported",1,proc_low," < 35s","nikto13",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #65
                ["0 item(s) reported",1,proc_low," < 35s","nikto14","ERROR: Cannot resolve hostname , 0 item(s) reported"],

                #66
                ["#1",0,proc_high," < 30m","dnsmap_brute",["[+] 0 (sub)domains and 0 IP address(es) found"]],

                #67
                ["open",0,proc_low," < 15s","nmapmssql",["Failed to resolve"]],

                #68
                ["open",0,proc_low," < 15s","nmapmysql",["Failed to resolve"]],

                #69
                ["open",0,proc_low," < 15s","nmaporacle",["Failed to resolve"]],

                #70
                ["open",0,proc_low," < 15s","nmapudprdp",["Failed to resolve"]],

                #71
                ["open",0,proc_low," < 15s","nmaptcprdp",["Failed to resolve"]],

                #72
                ["open",0,proc_high," > 50m","nmapfulltcp",["Failed to resolve"]],

                #73
                ["open",0,proc_high," > 75m","nmapfulludp",["Failed to resolve"]],

                #74
                ["open",0,proc_low," < 30s","nmapsnmp",["Failed to resolve"]],

                #75
                ["Microsoft SQL Server Error Log",0,proc_low," < 30s","elmahxd",["unable to resolve host address","Connection timed out"]],

                #76
                ["open",0,proc_low," < 20s","nmaptcpsmb",["Failed to resolve"]],

                #77
                ["open",0,proc_low," < 20s","nmapudpsmb",["Failed to resolve"]],

                #78
                ["Host:",0,proc_med," < 5m","wapiti",["none"]],

                #79
                ["WebDAV is ENABLED",0,proc_low," < 40s","nmapwebdaviis",["Failed to resolve"]],

                #80
                ["X-XSS-Protection[1",1,proc_med," < 3m","whatweb",["Timed out","Socket error","X-XSS-Protection[1"]],

                #81
                ["No names were discovered",1,proc_med," < 15m","amass",["The system was unable to build the pool of resolvers"]]



            ]



# Tool Set
 tools_precheck = [
                     ["nmap"],  ["uniscan"], ["fierce"], ["dnswalk"], ["whois"], ["sslyze"], ["lbd"], ["golismero"], ["dnsenum"],["nikto"], 
                 ]

 def get_parser():

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-h', '--help', action='store_true', 
                        help='Show help message and exit.')
    parser.add_argument('-u', '--update', action='store_true', 
                        help='Update RapidScan.')
    parser.add_argument('-s', '--skip', action='append', default=[],
                        help='Skip some tools', choices=[t[0] for t in tools_precheck])
    parser.add_argument('-n', '--nospinner', action='store_true', 
                        help='Disable the idle loader/spinner.')
    parser.add_argument('target', nargs='?', metavar='URL', help='URL to scan.', default='', type=str)
    return parser


# Shuffling Scan Order (starts)
 scan_shuffle = list(zip(tool_names, tool_cmd, tool_resp, tool_status))
 random.shuffle(scan_shuffle)
 tool_names, tool_cmd, tool_resp, tool_status = zip(*scan_shuffle)
 tool_checks = (len(tool_names) + len(tool_resp) + len(tool_status)) / 3 # Cross verification incase, breaks.
 tool_checks = round(tool_checks)
# Shuffling Scan Order (ends)

# Tool Head Pointer: (can be increased but certain tools will be skipped)
 tool = 0

# Run Test
 runTest = 1

# For accessing list/dictionary elements
 arg1 = 0
 arg2 = 1
 arg3 = 2
 arg4 = 3
 arg5 = 4
 arg6 = 5

# Detected Vulnerabilities [will be dynamically populated]
 rs_vul_list = list()
 rs_vul_num = 0
 rs_vul = 0

# Total Time Elapsed
 rs_total_elapsed = 0

# Tool Pre Checker
 rs_avail_tools = 0

# Checks Skipped
 rs_skipped_checks = 0



 args_namespace = get_parser().parse_args()

 if args_namespace.nospinner:
    spinner.disabled = True


 elif args_namespace.update:
    
    
    spinner.start()
    # Checking internet connectivity first...
    rs_internet_availability = check_internet()
    if rs_internet_availability == 0:
        print("\t"+ bcolors.BG_ERR_TXT + "There seems to be some problem connecting to the internet. Please try again or later." +bcolors.ENDC)
        spinner.stop()
        sys.exit(1)
   
    oldversion_hash = subprocess.check_output(cmd, shell=True)
    oldversion_hash = oldversion_hash.strip()
   
    newversion_hash = subprocess.check_output(cmd, shell=True)
    newversion_hash = newversion_hash.strip()
   
    spinner.stop()
    sys.exit(1)

 elif args_namespace.target:

    target = url_maker(args_namespace.target)
   
    os.system('rm /tmp/te* > /dev/null 2>&1') # Clearing previous scan files
    
    os.system('setterm -cursor off')
    
    print(bcolors.BG_HEAD_TXT+"[ Checking Available Security Scanning Tools Phase... Initiated. ]"+bcolors.ENDC)

    unavail_tools_names = list()

    while (rs_avail_tools < len(tools_precheck)):
        precmd = str(tools_precheck[rs_avail_tools][arg1])
        try:
            p = subprocess.Popen([precmd], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,shell=True)
            output, err = p.communicate()
            val = output + err
        except:
            print("\t"+bcolors.BG_ERR_TXT+"RapidScan was terminated abruptly..."+bcolors.ENDC)
            sys.exit(1)
        
        # If the tool is not found or it's part of the --skip argument(s), disabling it
        if b"not found" in val or tools_precheck[rs_avail_tools][arg1] in args_namespace.skip :
            if b"not found" in val:
                print("\t"+bcolors.OKBLUE+tools_precheck[rs_avail_tools][arg1]+bcolors.ENDC+bcolors.BADFAIL+"...unavailable."+bcolors.ENDC)
            elif tools_precheck[rs_avail_tools][arg1] in args_namespace.skip :
                print("\t"+bcolors.OKBLUE+tools_precheck[rs_avail_tools][arg1]+bcolors.ENDC+bcolors.BADFAIL+"...skipped."+bcolors.ENDC)
            
            for scanner_index, scanner_val in enumerate(tool_names):
                if scanner_val[2] == tools_precheck[rs_avail_tools][arg1]:
                    scanner_val[3] = 0 # disabling scanner as it's not available.
                    unavail_tools_names.append(tools_precheck[rs_avail_tools][arg1])

        else:
            print("\t"+bcolors.OKBLUE+tools_precheck[rs_avail_tools][arg1]+bcolors.ENDC+bcolors.OKGREEN+"...available."+bcolors.ENDC)
        rs_avail_tools = rs_avail_tools + 1
        
    unavail_tools_names = list(set(unavail_tools_names))
    if len(unavail_tools_names) == 0:
        print("\t"+bcolors.OKGREEN+"All Scanning Tools are available. Complete vulnerability checks will be performed by RapidScan."+bcolors.ENDC)
    else:
        print("\t"+bcolors.WARNING+"Some of these tools "+bcolors.BADFAIL+str(unavail_tools_names)+bcolors.ENDC+bcolors.WARNING+" are unavailable or will be skipped. RapidScan will still perform the rest of the tests. Install these tools to fully utilize the functionality of RapidScan."+bcolors.ENDC)
    print(bcolors.BG_ENDL_TXT+"[ Checking Available Security Scanning Tools Phase... Completed. ]"+bcolors.ENDC)
    print("\n")
    print(bcolors.BG_HEAD_TXT+"[ Preliminary Scan Phase Initiated... Loaded "+str(tool_checks)+" vulnerability checks. ]"+bcolors.ENDC)
    
    while(tool < len(tool_names)):
        print("["+tool_status[tool][arg3]+tool_status[tool][arg4]+"] Deploying "+str(tool+1)+"/"+str(tool_checks)+" | "+bcolors.OKBLUE+tool_names[tool][arg2]+bcolors.ENDC,)
        if tool_names[tool][arg4] == 0:
            print(bcolors.WARNING+"\nScanning Tool Unavailable. Skipping Test...\n"+bcolors.ENDC)
            rs_skipped_checks = rs_skipped_checks + 1
            tool = tool + 1
            continue
        try:
            spinner.start()
        except Exception as e:
            print("\n")
        scan_start = time.time()
        temp_file = "/tmp/rapidscan_temp_"+tool_names[tool][arg1]
        cmd = tool_cmd[tool][arg1]+target+tool_cmd[tool][arg2]+" > "+temp_file+" 2>&1"

        try:
            subprocess.check_output(cmd, shell=True)
        except KeyboardInterrupt:
            runTest = 0
        except:
            runTest = 1

        if runTest == 1:
                spinner.stop()
                scan_stop = time.time()
                elapsed = scan_stop - scan_start
                rs_total_elapsed = rs_total_elapsed + elapsed
                
                sys.stdout.write(ERASE_LINE)
                print(bcolors.OKBLUE+"\nScan Completed in "+display_time(int(elapsed))+bcolors.ENDC, end='\r', flush=True)
                print("\n")
                
                rs_tool_output_file = open(temp_file).read()
                if tool_status[tool][arg2] == 0:
                    if tool_status[tool][arg1].lower() in rs_tool_output_file.lower():
                       
                       
                        rs_vul_list.append(tool_names[tool][arg1]+"*"+tool_names[tool][arg2])
                else:
                    if any(i in rs_tool_output_file for i in tool_status[tool][arg6]):
                        m = 1 # This does nothing.
                    else:
                       
                        rs_vul_list.append(tool_names[tool][arg1]+"*"+tool_names[tool][arg2])
        else:
                runTest = 1
                spinner.stop()
                scan_stop = time.time()
                elapsed = scan_stop - scan_start
                rs_total_elapsed = rs_total_elapsed + elapsed
                
                sys.stdout.write(ERASE_LINE)
               
                print(bcolors.OKBLUE+"\nScan Interrupted in "+display_time(int(elapsed))+bcolors.ENDC, end='\r', flush=True)
                print("\n"+bcolors.WARNING + "\tTest Skipped. Performing Next. Press Ctrl+Z to Quit RapidScan.\n" + bcolors.ENDC)
                rs_skipped_checks = rs_skipped_checks + 1

        tool=tool+1

    print(bcolors.BG_ENDL_TXT+"[ Preliminary Scan Phase Completed. ]"+bcolors.ENDC)
    print("\n")

    #################### Report & Documentation Phase ###########################
    print(bcolors.BG_HEAD_TXT+"[ Report Generation Phase Initiated. ]"+bcolors.ENDC)
    if len(rs_vul_list)==0:
        print("\t"+bcolors.OKGREEN+"No Vulnerabilities Detected."+bcolors.ENDC)
    else:
        with open("RS-Vulnerability-Report", "a") as report:
            while(rs_vul < len(rs_vul_list)):
                vuln_info = rs_vul_list[rs_vul].split('*')
                report.write(vuln_info[arg2])
                report.write("\n------------------------\n\n")
                temp_report_name = "/tmp/rapidscan_temp_"+vuln_info[arg1]
                with open(temp_report_name, 'r') as temp_report:
                    data = temp_report.read()
                    report.write(data)
                    report.write("\n\n")
                temp_report.close()
                rs_vul = rs_vul + 1

            print("\tComplete Vulnerability Report for "+bcolors.OKBLUE+target+bcolors.ENDC+" named "+bcolors.OKGREEN+"`RS-Vulnerability-Report`"+bcolors.ENDC+" is available under the same directory.")

        report.close()
    # Writing all scan files output into RS-Debug-ScanLog for debugging purposes.
    for file_index, file_name in enumerate(tool_names):
        with open("RS-Debug-ScanLog", "a") as report:
            try:
                with open("/tmp/rapidscan_temp_"+file_name[arg1], 'r') as temp_report:
                        data = temp_report.read()
                        report.write(file_name[arg2])
                        report.write("\n------------------------\n\n")
                        report.write(data)
                        report.write("\n\n")
                temp_report.close()
            except:
                break
        report.close()

    print("\tTotal Number of Vulnerability Checks        : "+bcolors.BOLD+bcolors.OKGREEN+str(len(tool_names))+bcolors.ENDC)
    print("\tTotal Number of Vulnerability Checks Skipped: "+bcolors.BOLD+bcolors.WARNING+str(rs_skipped_checks)+bcolors.ENDC)
    print("\tTotal Number of Vulnerabilities Detected    : "+bcolors.BOLD+bcolors.BADFAIL+str(len(rs_vul_list))+bcolors.ENDC)
    print("\tTotal Time Elapsed for the Scan             : "+bcolors.BOLD+bcolors.OKBLUE+display_time(int(rs_total_elapsed))+bcolors.ENDC)
    print("\n")
    print("\tFor Debugging Purposes, You can view the complete output generated by all the tools named "+bcolors.OKBLUE+"`RS-Debug-ScanLog`"+bcolors.ENDC+" under the same directory.")
    if len(rs_vul_list) > 0 :
      print(bcolors.BG_ERR_TXT+"[ THIS URL MIGHT BE INJECTABLE. ]"+bcolors.ENDC)
    print(bcolors.BG_ENDL_TXT+"[ Report Generation Phase Completed. ]"+bcolors.ENDC)
    
    
    os.system('rm /tmp/rapidscan_te* > /dev/null 2>&1') # Clearing previous scan files
 exit




def help_open():
  resultat_window = Tk()
  resultat_window.title("BoostSecurityDB help")
  resultat_window.geometry("650x410+340+10")
  label_titel = Label(resultat_window,text="Welcome to BoostSecurityDB help ",font=("Tajawal",15,'bold italic'),bg='brown',fg='white')
  label_titel.place(x=130,y=10)
  
  f6=Frame(resultat_window,width=610,height=85,bg='azure3' ,bd=3,relief=GROOVE)
  f6.place(x=20 , y=55)
  
  abel_check = Label(resultat_window,text="__To get databases name write:__",font=("Tajawal",12,'italic'),bg='azure3',fg='black', highlightthickness=2 , highlightbackground='brown')
  abel_check.place(x=30 ,y=65)
  
  button1 = Button(resultat_window, width=25, text ="--url your site --donner-bases" , font=("Tajawal",10,'italic'),bg='white' , fg='brown' ,highlightthickness=2 ,highlightbackground='black')
  button1.place(x=120, y=99)
  
  f7=Frame(resultat_window,width=610,height=85,bg='azure3' ,bd=3,relief=GROOVE)
  f7.place(x=20 , y=150)
  
  abel_check2= Label(resultat_window,text="__To get databases tables write:__",font=("Tajawal",12,'italic'),bg='azure3',fg='black', highlightthickness=2 , highlightbackground='brown')
  abel_check2.place(x=30,y=160)
  
  button2 = Button(resultat_window, width=50, text ="--url your site --donner-table  --Database-nom nom de la basse " , font=("Tajawal",10,'italic'),bg='white' , fg='brown' ,highlightthickness=2 ,highlightbackground='black')
  button2.place(x=80, y=195)
  
  f8=Frame(resultat_window,width=610,height=85,bg='azure3' ,bd=3,relief=GROOVE)
  f8.place(x=20 , y=250)
  
  abel_check5= Label(resultat_window,text="__To get tables colomns write:__",font=("Tajawal",11,'italic'),bg='azure3',fg='black', highlightthickness=2 , highlightbackground='brown')
  abel_check5.place(x=30,y=260)
  
  button3 = Button(resultat_window, width=70, text ="--url your site --donner-colonnes --Database-nom nom de la basse --Table-nom nom de table" , font=("Tajawal",9,'italic'),bg='white' , fg='brown' ,highlightthickness=2 ,highlightbackground='black')
  button3.place(x=35, y=290)
 

  button1 = Button(resultat_window, width=13, text ="Exit" , font=("Tajawal",13,'italic bold'),bg='brown' , fg='black' ,command=sys.exit)
  button1.place(x=240, y=350)



    
window = Tk()
window.title("BoostSecurityDB")
window.geometry("650x410+340+10")

window.config(background='azure2')
window.columnconfigure(0,weight=1) #set all content in center
#frame 
f1=Frame(window,width=580,height=100,bg='azure3' ,bd=3,relief=GROOVE)
f1.place(x=30 , y=100)

f2=Frame(window,width=580,height=55,bg='azure3' ,bd=3,relief=GROOVE)
f2.place(x=30 , y=220)
#afficher texte
label_titel = Label(window,text="Welcome to <*BoostSecurityDB*>",font=("Tajawal",15,'bold italic'),bg='brown',fg='white')
label_titel.place(x=130,y=30)



#ajouter boutton check

button1 = Button(window, width=19, text ="Check nombre de vul " , font=("Tajawal",13,'italic'),bg='lightcoral' , fg='black' ,command=vuln)
button1.place(x=200,y=130)

#boutton save
button_save = Button(window, width=13, text ="Check " , font=("Tajawal",13,'italic'),bg='lightcoral' , fg='black' ,command=function_sqlmap)
button_save.place(x=420,y=230)
button_save = Button(window, width=13, text ="Help" , font=("Tajawal",13,'italic'),bg='lightcoral' , fg='black' ,command=help_open)
button_save.place(x=60,y=230)

button1 = Button(window, width=13, text ="Exit" , font=("Tajawal",13,'bold italic'),bg='red' , fg='black' ,command=sys.exit)
button1.place(x=240, y=310)

#developer label
developerlabel = Label(window, text="created by", font=("Tajawal",9,'italic'),bg='azure2')
developerlabel.place(x=280, y=350)
developerlabel1 = Label(window, text=" © Ms.Daoud_Marwa & Dr.Hamdane Mohamed El kamel", font=("Tajawal",9,'italic'),bg='azure2')
developerlabel1.place(x=160, y=370)
#afficher
window.mainloop()