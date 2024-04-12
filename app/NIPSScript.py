from elasticsearch import Elasticsearch
from elasticsearch.helpers import scan
from sklearn.tree import DecisionTreeClassifier

import pandas as pd
from time import sleep
import sys
import os
import subprocess
import threading
from datetime import datetime


args = sys.argv[1:]

lastTimestamp = 0

netFlowRecords = pd.DataFrame()

parsedNetFlowRecords = pd.dataframe()

jobs = []

esClient = Elasticsearch('http://localhost:9200',basic_auth=["elastic","changeme"]) # change to args
        

paper19Features = ["FLOW_DURATION_MILLISECONDS", 
                        "TCP_WIN_MAX_IN", "DURATION_OUT", 
                        "MAX_TTL", "L7_PROTO", 
                        "SRC_TO_DST_AVG_THROUGHPUT", 
                        "SHORTEST_FLOW_PKT", "MIN_IP_PKT_LEN", 
                        "TCP_WIN_MAX_OUT", "OUT_BYTES"]

def aggregateFlows(allFlows, ipAddr):
    filteredFlows = allFlows[allFlows["source.ip"] == ipAddr] # && dest = dest or no?
    aggregatedFlows = pd.DataFrame([filteredFlows.sum().values],columns=allFlows.index)
    return aggregatedFlows

def GetFeatures(allflows):
    _FLOW_DURATION_MILLISECONDS = (LAST_SWITCHED - FIRST_SWITCHED) * 1000
    _DURATION_OUT = aggregateFlows()
    _MAX_TTL = MAX_TTL
    _L7_PROTO = enumerateL7Proto()
    _SRC_TO_DST_AVG_THROUGHPUT = 0#\frac{\text{IN_BYTES + OUT_BYTES}{\text{LAST_SWITCHED} - \text{FIRST_SWITCHED}} \times 8
    _SHORTEST_FLOW_PKT = MAX_IP_PKT_LEN if MIN_IP_LEN = 0 else MAX_IP_PKT_LEN 
    MIN_IP_PKT_LEN = MIN_IP_LEN
    _OUT_BYTES = OUT_BYTES

    return  

# Initialize basic static routing
def addStaticRoutes():
    with open('NIPS/app/routes.txt', 'r') as routesFile:
        for line in routesFile:
            subprocess.run(line.split())

def blockIP(ip):
    subprocess.run(line.split()) # block ip command IPTables of UFW

# Log messages to Elasticsearch
def logToElastic(logLevel,message, exception):
    doc = {
    'author': 'NIPS',
    'log level': logLevel,
    'message' : message,
    'exception' : str(exception),
    '@Timestamp': datetime.now().isoformat()
    }
    result = esClient.index(index="nips", document=doc)
    print(result['result'])

def getFlowRecords(flowRecords,jobs,esClient, lastTimestamp):
    flowRecords = pd.DataFrame()
    while True:
        # Query for flowRecords with lastTimestamp greater than the last one we processed
        query = {
            "query": {
                "range" : {
                    "@timestamp" : {
                        "gt" : lastTimestamp # change to -2hr
                    }
                }
            },
            "size" : 100
        }

        result = scan(client=esClient,             
                query=query,                                     
                scroll='1m',
                index='elastiflow-*',
                raise_on_error=True,
                preserve_order=True,
                clear_scroll=True)
        
        result = list(result)

        # Process the flowRecords
        try:
            for record in result:
                # Update the lastTimestamp if this record's timestamp is greater
                lastTimestamp = max(lastTimestamp, record['_source']['@timestamp'])
                # Add new IP to be processed by DT
                if(record['_source']['source.ip'] not in jobs):
                    jobs.append(record['_source']['source.ip'])
                flowRecords = pd.concat([flowRecords,pd.DataFrame.from_dict(record['_source'])],ignore_index=True)
                flowRecords.sort_values(by=flowRecords.columns[0], inplace=True)
                flowRecords = flowRecords.reset_index(drop=True)
                print(flowRecords.head)        
            #flowRecords.to_json("netflowData.json")
            # Sleep for a bit before querying again
            sleep(1)
        except Exception as e:
            logToElastic("ERROR", "Failed to retrieve records", e)

def loadModels():
    # Load machine learning models
    try:
        return DecisionTreeClassifier(), DecisionTreeClassifier() # read from joblib file
    except Exception as e:
        logToElastic("ERROR","Failed to load machine learning models", e)
        exit()
    
def Level1FlowPredictor(flow, model):
    # Perform binary prediction using the provided model
    try:
        binaryPrediction = model.predict(flow)
        print(binaryPrediction, type(binaryPrediction))
        logToElastic("INFO","Binary prediction", binaryPrediction)
        return binaryPrediction
    except Exception as e:
        logToElastic("ERROR","Failed to perform Level 1 flow prediction", e)
        return None

def Level2FlowPredictor(flow, model):
    # Perform multi-class prediction using the provided model
    try:
        multiPrediction = model.predict(flow)
        print(multiPrediction, type(multiPrediction))
        logToElastic("INFO", "Multi-class prediction", multiPrediction)
        return multiPrediction
    except Exception as e:
        logToElastic("ERROR","Failed to perform Level 2 flow prediction", e)
        return None

def main():

    level1Model, level2Model  = loadModels()

    # Thread to fetch flow records
    fetchFlowsThread = threading.Thread(target=getFlowRecords, args=(netFlowRecords, jobs, esClient, lastTimestamp,))
    fetchFlowsThread.start()

    # Main-Thread to analyze flow records
    while True:
        try:
            for job in jobs:
                aggregatedFlow = aggregateFlows(netFlowRecords,job)
                binaryPrediction = Level1FlowPredictor(aggregatedFlow[paper19Features], level1Model)
                if binaryPrediction == 1:
                    logToElastic("INFO","Attack detected from: ", job)
                    multiclassPrediction = Level2FlowPredictor(aggregatedFlow,level2Model)
                    # do smtg
            sleep(1)
        except KeyboardInterrupt:
            logToElastic("INFO","Received KeyboardInterrupt. Exiting...", None)
            break
        except Exception as e:
            logToElastic("ERROR","An error occurred in the main loop", e)
            break

if __name__ == "__main__":
    main()


# "FLOW_DURATION_MILLISECONDS", = [161][Len 4] %FLOW_DURATION_MILLISECONDS %flowDurationMilliseconds    Flow duration (msec), Flow duration (milliseconds)=(LAST_SWITCHED−FIRST_SWITCHED)×1000
# "TCP_WIN_MAX_IN", = [NFv9 57888][IPFIX 35632.416][Len 2] %TCP_WIN_MAX_IN                  Max TCP Window (src->dst)
# "DURATION_OUT", = [NFv9 57864][IPFIX 35632.392][Len 4] %DURATION_OUT                    Client to Server stream duration (msec)
#     Identify Client-to-Server Communication: Since the table doesn't explicitly mention client and server, we need to infer it. Typically, in TCP communication, the client initiates the connection, and the server responds. Therefore, for flows with TCP traffic, you can assume that the flow direction from the client to the server is the outgoing direction (%DURATION_OUT).
# Calculate Duration: To calculate the duration of the stream, we can use the FIRST_SWITCHED and LAST_SWITCHED fields. These fields indicate the system uptime at which the first and last packets of the flow were switched, respectively.

# Convert to Milliseconds: Once you have the duration in seconds, you can convert it to milliseconds by multiplying it by 1000.

#Here's the formula:\text{%DURATION_OUT} = (\text{LAST_SWITCHED} - \text{FIRST_SWITCHED}) \times 1000

#You'll need to look for flows that represent communication from the client to the server (you might infer this based on the source and destination IP addresses, assuming the client initiates the connection). Then, calculate the duration using the provided fields.

# "MAX_TTL", = MAX_TTL, 53 1 Maximum TTL on incoming packets of the flow
# "L7_PROTO", = enumeration of Layer 7, [NFv9 57590][IPFIX 35632.118][Len 2] %L7_PROTO                        Layer 7 protocol (numeric), check port numbers ig
# "SRC_TO_DST_AVG_THROUGHPUT", = [NFv9 57556][IPFIX 35632.84][Len 4] %SRC_TO_DST_AVG_THROUGHPUT        Src to dst average thpt (bps)
#     To calculate the average throughput from source to destination (SRC_TO_DST_AVG_THROUGHPUT) in bits per second (bps), you need to use the available fields in the table and perform the necessary calculations. Since there's no explicit field for throughput provided in the table, we'll need to approximate it using other available information.

# Here's how you can approach it:

# Calculate Total Bytes Transferred: Use the fields IN_BYTES and OUT_BYTES to calculate the total number of bytes transferred from source to destination.

# \text{Total Bytes Transferred} = \text{IN_BYTES} + \text{OUT_BYTES}

# Calculate Duration: Determine the duration of the flow, which can be obtained from the FIRST_SWITCHED and LAST_SWITCHED fields.

# \text{Flow Duration (seconds)} = (\text{LAST_SWITCHED} - \text{FIRST_SWITCHED})

# Convert Duration to Seconds: If the flow duration is not already in seconds, ensure it's converted to seconds.

# Calculate Throughput: Divide the total bytes transferred by the flow duration to get the average throughput in bytes per second (Bps). Then, convert it to bits per second (bps) by multiplying by 8.

# Throughput (bps)
# =
# Total Bytes Transferred
# Flow Duration (seconds)
# ×
# 8
# Throughput (bps)= 
# Flow Duration (seconds)
# Total Bytes Transferred
# ​
#  ×8

# Here's the formula combining these steps:

# \text{SRC_TO_DST_AVG_THROUGHPUT} = \frac{\text{IN_BYTES} + \text{OUT_BYTES}}{\text{LAST_SWITCHED} - \text{FIRST_SWITCHED}} \times 8

# "SHORTEST_FLOW_PKT", = [NFv9 57580][IPFIX 35632.108][Len 2] %SHORTEST_FLOW_PKT               Shortest packet (bytes) of the flow if, = MAX_IP_PKT_LEN if MIN_IP_LEN = 0 else MAX_IP_PKT_LEN  
# "MIN_IP_PKT_LEN", = MIN_PKT_LNGTH, [ 25][Len 2] %MIN_IP_PKT_LEN             %minimumIpTotalLength        Len of the smallest flow IP packet observed
# "TCP_WIN_MAX_OUT", = [NFv9 57892][IPFIX 35632.420][Len 2] %TCP_WIN_MAX_OUT                 Max TCP Window (dst->src)
    
# To calculate the maximum TCP window size (dst->src) using the fields provided in the table, you would follow a similar approach as with other calculations.

# Given the fields provided in your table, specifically TCP_FLAGS, which include cumulative TCP flags seen for the flow, you can make an inference about the TCP window size. The TCP window scale option (WSopt) is one of the TCP flags used to negotiate the window size during the TCP handshake. By examining the TCP_FLAGS, you might infer the presence of WSopt and potentially the window size negotiation.

# Here's a general outline of how you might approach this:

# Identify Flows with TCP Traffic: Look for flows with TCP traffic, typically indicated by PROTOCOL = 6.

# Examine TCP Flags: Examine the TCP_FLAGS field to identify flows where the TCP window scale option (WSopt) is negotiated.

# Infer Maximum TCP Window Size: If WSopt is negotiated, you can assume that the window size might have been scaled accordingly. However, you won't have the exact window size unless explicitly provided in the data.

# Here's how you could calculate it:

# \text{Max TCP Window (dst->src)} = \text{Value inferred from TCP_FLAGS}

# You will need to process your flow data to qqextract the relevant fields, filter for TCP flows, and determine the maximum TCP window size inferred from the TCP_FLAGS. However, please note that this method is an approximation and may not accurately reflect the true maximum TCP window size. For precise measurements, it's preferable to have direct access to the TCP window size data.

# "OUT_BYTES" = OUT_BYTES