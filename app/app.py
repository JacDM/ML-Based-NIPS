import pandas as pd
import numpy as np
import platform
import socket
import paramiko
import os

from sklearn.tree import DecisionTreeClassifier
from elasticsearch import Elasticsearch, ConnectionError, TransportError
from elasticsearch.helpers import scan
from datetime import datetime
from joblib import load
from time import sleep


port = 22 # SSH port (default is 22)



# Load Elasticsearch client
if (os.path.exists('/.dockerenv')):
    elasticPasswd = os.environ.get('ELASTIC_PASSWORD')
    esClient = Elasticsearch('http://elasticsearch:9200', basic_auth=["elastic", elasticPasswd])
    hostIP = socket.gethostbyname("host.docker.internal")
    username = os.environ.get('OS_USER')
    password = os.environ.get('OS_PASSWORD')
    consoleLogLevel = int(os.environ.get('LOG_LEVEL'))
    nipsMode = int(os.environ.get('NIPS_MODE'))
    timeFrame = os.environ.get('TIMEFRAME') 
    modelsPATH = "config/models/"
else: #needs to be setup if not running script on docker but on host OS
    esClient = Elasticsearch('http://localhost:9200', basic_auth=["elastic", "changeme"])
    hostIP = "127.0.0.1"
    username = "yourUsername"  # Replace with your username
    password = "yourPassword"  # Replace with your password
    consoleLogLevel = 1 #Replace with desired log level
    nipsMode = 0 #Enables IP Blockinf if attack is detected
    timeFrame = "5m" #Defines timeframe to lookback from for elastic
    modelsPATH = "app/config/models/"


def logToElastic(logLevel,message, exception):
    doc = {
    'author': 'NIPS',
    'log level': logLevel,
    'message' : message,
    'exception' : str(exception),
    '@Timestamp': datetime.now().isoformat()
    }
    try:
        result = esClient.index(index="nips", document=doc)
    except ConnectionError:
            print("ERROR: ConnectionError: Unable to connect to Elasticsearch. Check if Elasticsearch is running.")
            sleep(60)
            logToElastic(logLevel,message, exception)
    if(consoleLogLevel >= 1):
        if logLevel == "ATTACK" or logLevel == "INFO":
            print("LogLevel: "+logLevel)
            print(message)
            print("At time: "+doc['@Timestamp'])
        else:
            for key, value in doc.items():
                print(f"{key}: {value}")
# Load machine learning models
try:
    level1Classifier = load(modelsPATH + "L1Classifier.joblib")
    level2Classifier = load(modelsPATH + "L2Classifier.joblib")
    print("Loaded Models")
except Exception as e:
    logToElastic("ERROR","Failed to load machine learning models:", e)
    exit()

def blockIP(ipAddress):
    currentPlatform = platform.system()
    sshClient = paramiko.SSHClient()
    sshClient.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Execute platform-specific command to block the IP address
    if currentPlatform == 'Windows':
        command = ['netsh', 'advfirewall', 'firewall', 'add', 'rule', 'name="Block IP"', 'dir=in', 'interface=any', 'action=block', f'remoteip={ipAddress}']
    elif currentPlatform == 'Linux':
        command = ['iptables', '-A', 'INPUT', '-s', ipAddress, '-j', 'DROP']
    else:
        print("Unsupported platform only Linux And Windows")
        return
    try:
        sshClient.connect(hostname=hostIP, port=port, username=username, password=password)
        stdin, stdout, stderr = sshClient.exec_command(command)
        output = stdout.read().decode('utf-8')
        error = stderr.read().decode('utf-8')
        
        logToElastic("INFO",f"SSH Connection successfull,STDIN:{command},STDOUT: {output}, STDERR: {error}")
    except paramiko.AuthenticationException:
        logToElastic("ERROR","Authentication failed. Please check your SSH credentials.",None)
    except paramiko.SSHException as e:
        logToElastic("ERROR","SSH error",e)
    except Exception as e:
        logToElastic("ERROR","An error occurred", e)


paper19Features = ["FLOW_DURATION_MILLISECONDS", 
                   "TCP_WIN_MAX_IN", 
                   "DURATION_OUT", 
                   "MAX_TTL", 
                   "L7_PROTO", 
                   "SRC_TO_DST_AVG_THROUGHPUT", 
                   "SHORTEST_FLOW_PKT", 
                   "MIN_IP_PKT_LEN", 
                   "TCP_WIN_MAX_OUT", 
                   "OUT_BYTES"]


allFeatures = ['client.domain',
               'destination.domain', 
               'client.port', 
               'destination.port',
               'flow.export.msgs', 
               'event.duration', 
               'flow.in.tcp.window.size_max',
               'ntop.out.c2s.duration', 
               'ip.ttl_max',
               'app.id', 
               'flow.client.throughput_avg', 
               'flow.packet_size_min', 
               'ip.packet.size_min', 
               'flow.out.tcp.window.size_max', 
               'flow.out.bytes']

multiClassificationLabels = ['Class 0: Benign',
                             'Class 1: backdoor',
                             'Class 2: ddos',
                             'Class 3: dos',
                             'Class 4: injection',
                             'Class 5: mitm',
                             'Class 6: password',
                             'Class 7: ransomware',
                             'Class 8: scanning',
                             'Class 9: xss']

# Function to fetch flow records and perform classification
def fetchAndClassifyFlows():
    lastTimestamp = 0
    while True:
        try:
            # Query for flowRecords with lastTimestamp greater than the last one processed and within 2 hours
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {
                                "range": {
                                    "@timestamp": {
                                        "gt": "now-" + timeFrame
                                    }
                                }
                            },
                            {
                                "range": {
                                    "@timestamp": {
                                        "gt": lastTimestamp
                                    }
                                }
                            }
                        ]
                    }
                },
            }

            result = scan(client=esClient,             
                          query=query,                                     
                          scroll='1m',
                          index='elastiflow*',
                          raise_on_error=True,
                          preserve_order=True,
                          clear_scroll=True)
            
            for record in result:
                # Update the lastTimestamp if this record's timestamp is greater
                lastTimestamp = max(lastTimestamp, record['_source']['@timestamp'])

                subset = []
                for feature in allFeatures:
                    try:
                        subset.append(record['_source'][feature])
                    except:
                        subset.append(None)

                if(consoleLogLevel >=2):
                    print("Classifiying flow produced by: ",subset[0])
                if(subset[5] != None):
                    subset[5] = subset[5]/1000000000
                subsetFrame = np.array(subset[5:])
                subsetFrame = subsetFrame.reshape(1, -1)
                subsetFrame = pd.DataFrame(subsetFrame, columns=paper19Features, index=None)

                binaryPrediction = int(Level1FlowPredictor(subsetFrame)[0])
                if binaryPrediction == 1:
                    multiclassPrediction = int(Level2FlowPredictor(subsetFrame)[0])
                    if (multiclassPrediction == 0):
                        logToElastic("INFO",f"Attack Detected, Level-2-Classifier suggests it is: {multiClassificationLabels[multiclassPrediction]}. From: Source IP Address:  {subset[0]}, Source Port: {subset[2]}, To: Destination IP Address: {subset[1]}, Source Port: {subset[3]}",None)
                    else:
                        logToElastic("ATTACK",f"Attack Detected, Level-2-Classifier suggests it is: {multiClassificationLabels[multiclassPrediction]}. From: Source IP Address:  {subset[0]}, Source Port: {subset[2]}, To: Destination IP Address: {subset[1]}, Source Port: {subset[3]}",None)

                    if (nipsMode == 1):
                        blockIP(subset[0])
            # Sleep for a bit before querying again
            sleep(1)
        except ConnectionError:
            logToElastic("ERROR","ConnectionError: Unable to connect to Elasticsearch. Check if Elasticsearch is running.",None)
            sleep(60)
            fetchAndClassifyFlows()
        except KeyboardInterrupt:
            logToElastic("INFO","Received KeyboardInterrupt. Exiting...",None)
            break
        except Exception as e:
            logToElastic("ERROR","An error occurred within the main loop:", e)
            exit()

# Functions for flow classification
def Level1FlowPredictor(flow):
    try:
        binaryPrediction = level1Classifier.predict(flow)
        return binaryPrediction
    except Exception as e:
        logToElastic("Failed to perform Level 1 flow prediction:", e)
        return None

def Level2FlowPredictor(flow):
    try:
        multiPrediction = level2Classifier.predict(flow)
        return multiPrediction
    except Exception as e:
        print("Failed to perform Level 2 flow prediction:", e)
        return None

# Call the function to fetch and classify flows
fetchAndClassifyFlows()