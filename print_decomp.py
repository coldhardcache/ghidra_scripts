#Ghidra Script to output best C code decompilation for quick analysis
#Input parameter: target function
#Output : standard out C-style code of each function
#Goes through given binary, and finds calls to that function, outputs C-style code of calling function
#@category RE
#@author coldhardcache

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

import __main__ as ghidra_app

def run():
	#grab the argument from the script
	args = getScriptArgs()
	if len(args) != 1:
		print("No function name given!")
		exit(-1)
	targetfunc = args[0]

	#load project
	program = getCurrentProgram()
	ifc = DecompInterface()
	ifc.openProgram(program)
	fm = program.getFunctionManager()
	funcs = fm.getFunctions(True)

	#iterate through all functions, if function name matches and is not EXTERNAL (like trampoline), add it to matches
	matches = []
	for func in funcs:
		if func.getName() == targetfunc:
			section = currentProgram.getMemory().getBlock(func.getEntryPoint()).getName()
			if section != "EXTERNAL":
				matches.append(func)

	#iterate through the matches, condense the calling functions
	for func in matches:
		#print("\nFound '{}' @ 0x{}".format(targetfunc, func.getEntryPoint()))
		entry_point = func.getEntryPoint()
		references = getReferencesTo(entry_point)
		ref_addrs = set()
		for xref in references:
			ref_addrs.add(getFunctionContaining(xref.getFromAddress()))

	#iterate through functions, print out C code
	for function in ref_addrs:
		#print("Function: {} @ 0x{}".format(function.getName(), function.getEntryPoint()))
		results = ifc.decompileFunction(function, 0, ConsoleTaskMonitor())
		print(results.getDecompiledFunction().getC())

if __name__ == '__main__':
	run()

