import pandas as pd
import numpy as np
import subprocess
import platform
import os
from sklearn.tree import DecisionTreeClassifier
from elasticsearch import Elasticsearch, ConnectionError, TransportError
from elasticsearch.helpers import scan
from datetime import datetime
from joblib import load
from time import sleep

# Load Elasticsearch client
#elasticPasswd = os.environ.get('ELASTIC_PASSWORD')
#esClient = Elasticsearch('http://elasticsearch:9200', basic_auth=["elastic", elasticPasswd])
#Maybe different verbose modes
esClient = Elasticsearch('http://elasticsearch:9200', basic_auth=["elastic", "changeme"])

def logToElastic(logLevel,message, exception):
    doc = {
    'author': 'NIPS',
    'log level': logLevel,
    'message' : message,
    'exception' : str(exception),
    '@Timestamp': datetime.now().isoformat()
    }
    result = esClient.index(index="nips", document=doc)
    for key, value in doc.items():
        print(f"{key}: {value}")

# Load machine learning models
try:
    level1Classifier = load("config/models/L1Classifier.joblib")
    level2Classifier = load("config/models/L2Classifier.joblib")
    print("Loaded Models")
except Exception as e:
    logToElastic("ERROR","Failed to load machine learning models:", e)
    exit()

def blockIP(ip_address):
    current_platform = platform.system()

    # Execute platform-specific command to block the IP address
    if current_platform == 'Windows':
        command = ['netsh', 'advfirewall', 'firewall', 'add', 'rule', 'name="Block IP"', 'dir=in', 'interface=any', 'action=block', f'remoteip={ip_address}']
    elif current_platform == 'Linux':
        command = ['iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP']
    else:
        print("Unsupported platform only Linux And Windows")
        return

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        logToElastic("INFO","Blocked IP",result.stdout)
    except subprocess.CalledProcessError as e:
        logToElastic("ERROR","Error blocking IP", {e.stderr})
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
                                        "gt": "now-24h"
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
                
                print("Classifiying flow produced by: ",subset[0])
                subsetFrame = np.array(subset[5:])
                subsetFrame = subsetFrame.reshape(1, -1)
                subsetFrame = pd.DataFrame(subsetFrame, columns=paper19Features, index=None)

                binaryPrediction = int(Level1FlowPredictor(subsetFrame)[0])
                if binaryPrediction == 1:
                    multiclassPrediction = int(Level2FlowPredictor(subsetFrame)[0])
                    logToElastic("INFO",f"Attack Detected, Level-2-Classifier suggests: {multiClassificationLabels[multiclassPrediction]}. From: Source IP Address:  {subset[0]}, Source Port: {subset[2]}, To: Destination IP Address: {subset[1]}, Source Port: {subset[3]}",None)

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