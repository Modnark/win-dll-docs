import os
import json
import pefile
import time
import os
import ctypes
from ctypes import wintypes

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
        print(f"Error getting time for {filename}")
        os.unlink(os.path.abspath(filename))
    
    return peEpoch, peTimeStamp

def getImportsAndExports(filename):
    imports = {}
    exports = []
    
    try:
        pe = pefile.PE(filename)
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                exports.append(exp.name.decode('utf-8'))
        
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            entrydll = entry.dll.decode("utf-8").lower()
            imports[entrydll] = []

            for imp in entry.imports:
                if imp.name:
                    imports[entrydll].append(imp.name.decode('utf-8'))
    except:
        print(f"Error getting imports / exports for: {filename}") 
    
    return imports, exports
    
def saveJSONS(jsonFullPath, jsonDir, resDir, baseName, fullPath):
    # Gather info
    currentPETime = getPETime(fullPath)
    imports, exports = getImportsAndExports(fullPath)  
    
    # Construct info structure
    infoJson = {}
    infoJson["fileName"] = baseName
    infoJson["isoPath"] = jsonFullPath
    
    # PETime
    infoJson["PETime"] = {}
    infoJson["PETime"]["epoch"] = currentPETime[0]
    infoJson["PETime"]["UTC"] = currentPETime[1]
    
    # Imports / Exports
    infoJson["ImportsExports"] = {}
    infoJson["ImportsExports"]["imports"] = imports
    infoJson["ImportsExports"]["exports"] = exports
    
    # Resources
    
    # Write info to file
    infoJsonFile = open(f"{jsonDir}\\{baseName}.json", "w")
    infoJsonFile.write(json.dumps(infoJson))