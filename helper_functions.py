import os
import json
import pefile
import time
import os

# Make a directory if it doesn't exist
def mkdirifnot(dirName):
    if os.path.exists(dirName):
        return
    os.mkdir(dirName)
    
def getPETime(filename):
    peEpoch = None
    peTimeStamp = None
    
    try:
        pe = pefile.PE(filename)
        peEpoch = pe.FILE_HEADER.TimeDateStamp
        peTimeStamp = time.asctime(time.gmtime(peEpoch))
    except:
        print(f"Error parsing {filename}")
        os.unlink(os.path.abspath(filename))
    
    return peEpoch, peTimeStamp
    
def saveJSONS(jsonFullPath, jsonDir, baseName, fullPath):
    currentPETime = getPETime(fullPath)
    fileMapDict = {"fileName": baseName, "isoPath": jsonFullPath, "peTime": {"epoch": currentPETime[0], "UTC": currentPETime[1]}}
    fileMap = open(f"{jsonDir}\\{baseName}.json", "w")
    fileMap.write(json.dumps(fileMapDict))