import os
import helper_functions as helpers
import iso_extract
from py7zr import unpack_7zarchive
import shutil
import traceback
import subprocess
import json

# Specify Base (isos) and Output folders (results)
# isoFolder is normally located in the same directory as the py file
isoFolder = "isos"
resultFolder = "results"
isoList = []

# Get ISOs inside of isoFolder and put it into isoList
for iso in os.listdir(isoFolder):
    if iso.endswith(".iso"):
        isoList.append(iso)
        
# Extract ISOs
helpers.mkdirifnot(f"{isoFolder}\\extracted")

# Process through each ISO
for iso in isoList:
    print(f"Extracting {iso}...")

    try:
        # Get the ISO name and then make it the name of the folder.
        # It should be noted that due to windows file length restrictions,
        # you should rename the ISO to be short.
        isoFolderName = iso.strip(".iso")
        rootDir = f"{isoFolder}\\extracted\\{isoFolderName}" # isos\extracted\ISONAME\
        extractIsoDir = f"{rootDir}\\iso" # isos\extracted\ISONAME\iso
        extractDllDir = f"{rootDir}\\dll" # isos\extracted\ISONAME\dll
        jsonDir = f"{rootDir}\\json" # isos\extracted\ISONAME\dll
        resDir = f"{rootDir}\\resources" # isos\extracted\ISONAME\resources
        helpers.mkdirifnot(rootDir) # Create isos\extracted\ISONAME\
        helpers.mkdirifnot(extractIsoDir) # Create isos\extracted\ISONAME\iso
        helpers.mkdirifnot(extractDllDir) # Create isos\extracted\ISONAME\dll
        helpers.mkdirifnot(jsonDir) # Create isos\extracted\ISONAME\dll
        helpers.mkdirifnot(resDir) # Create isos\extracted\ISONAME\resources
        
        # Extract the ISO's contents
        print("Extracting ISO files...")
        iso_extract.extract_iso("auto", "/", extractIsoDir, f"{isoFolder}\\{iso}")
        
        print("Extracting CAB files...")
        for root, subdirs, files, in os.walk(extractIsoDir):
            for _file in files:
                lowerFile = _file.lower()
                fullPath = f"{root}\\{_file}" # extractIsoDir\DLLNAME.dll
                isDL_ = lowerFile.endswith(".dl_")                
                
                if isDL_:
                    cwdPath = os.path.abspath(fullPath)
                    subprocess.Popen(f"7z x {cwdPath} -y", cwd=os.path.dirname(cwdPath)).wait()   
        
        # Gather necessary information from DLLs
        print("Collecting information...")
        for root, subdirs, files, in os.walk(extractIsoDir):
            for _file in files:
                lowerFile = _file.lower()
                fullPath = f"{root}\\{_file}" # extractIsoDir\(SUB-DIRECTORIES)\DLLNAME.dll
                jsonFullPath = fullPath.strip(extractIsoDir) # (SUB-DIRECTORIES)\DLLNAME.dll
                isDLL = lowerFile.endswith(".dll")
                
                if isDLL:
                    if not os.path.exists(f"{extractDllDir}\\{lowerFile}"):
                        shutil.move(os.path.abspath(fullPath), extractDllDir)
                        helpers.saveJSONS(jsonFullPath, jsonDir, resDir, lowerFile, f"{extractDllDir}\\{lowerFile}")
                     
        # all done, cleanup
        print(f"Finished extracting {iso}!")
        shutil.rmtree(extractIsoDir)
        
    except Exception as e:
        with open("errors.txt", "w") as eLog:
            tb = traceback.format_exc()
            print("ERROR HAPPENED ABORTING MISSION!")
            print("Here's the error too:")
            print(tb)
            eLog.write(tb)
            shutil.rmtree(rootDir)
            exit()