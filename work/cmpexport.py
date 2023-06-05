import pefile
import os
from pathlib import Path

#exports = []
imports = {}
	
importsi = input("imports: ")
exportsi = input("exports directory: ")

#TODO ordinals

pe1 =  pefile.PE(importsi)
#pe2 =  pefile.PE(exportsi)

def getexports(fstr):
	exports = []
	#if os.path.exists(fstr):
	for path in Path(exportsi).rglob(fstr):
		pe =  pefile.PE(path)
		for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
			if exp.name:
				exports.append(exp.name.decode('utf-8'))
	#if there are no exports then it means the dll wasnt found
	if len(exports) != 0:
		return exports
	else:
		print("ERROR export dll not found")
		return []

def listsubtract(list1,list2):
	result = []
	for element in list1:
		if not element in list2:
			result.append(element)
	return result
	
def printlist(list):
	for element in list:
		print(element)

for entry in pe1.DIRECTORY_ENTRY_IMPORT:
	entrydll = entry.dll.decode("utf-8").lower()
	imports[entrydll] = []
	#entry.dll
	for imp in entry.imports:
		if imp.name:
			imports[entrydll].append(imp.name.decode('utf-8'))
			

for importdll in imports:
	print("\n	"+importdll.upper())
	#for oimport in imports[importdll]:
	exports = getexports(importdll)
	if len(exports) > 0:
		listsub = listsubtract(imports[importdll], exports)
		if len(listsub) != 0:
			printlist(listsub)
		else:
			print("No exports missing!")
	else:
		continue
	
		#print(oimport)
#for exp in pe2.DIRECTORY_ENTRY_EXPORT.symbols:
	#exports.append(exp.name.decode('utf-8'))
  
#for oimport in imports:
#	if not oimport in exports:
#		print(oimport)