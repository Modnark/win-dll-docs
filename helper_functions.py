import os
import getPETimeStamp as petime
import json

# Make a directory if it doesn't exist
def mkdirifnot(dirName):
    if os.path.exists(dirName):
        return
    os.mkdir(dirName)
    
def SaveJSONS(jsonFullPath, jsonDir, baseName, fullPath):
    print(fullPath)
    currentPETime = petime.getBoth(fullPath)
    fileMapDict = [{"fileName": baseName, "isoPath": jsonFullPath, "peTime": {"epoch": currentPETime[0], "UTC": currentPETime[1]}}]
    fileMap = open(f"{jsonDir}\\{baseName}.json", "w")
    fileMap.write(json.dumps(fileMapDict))