
/* ###
 * IP: GHIDRA
 * REVIEWED: YES
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
//Iterates over all functions in the current program.
//@category Iteration

import java.io.File;
import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Set;
import java.util.Date;
import java.sql.Timestamp;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.lang.Register;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.*;
import ghidra.program.model.listing.*;
import java.io.*;

public class AnalysisARMTool extends GhidraScript {

	@Override
	public void run() throws Exception {
		analysis();
	}

	private void analysis() {
		PrintWriter pWriter;
                PrintWriter timeWriter;
		try {
			String[] args = getScriptArgs();
			String RawSuffix = args[0];
			File startTimeFile = new File(currentProgram.getExecutablePath()+RawSuffix+".monitor3_ts");
			if (!startTimeFile.exists()){
				startTimeFile.createNewFile();
			}
			timeWriter = new PrintWriter(new FileOutputStream(startTimeFile));
			Date date = new Date();
                        timeWriter.println(String.valueOf(date.getTime()));
                        timeWriter.close();

			println(currentProgram.getExecutablePath());
			File outputNameFile = new File(currentProgram.getExecutablePath()+RawSuffix );
			if (!outputNameFile.exists()) {
				outputNameFile.createNewFile();
			}
			pWriter = new PrintWriter(new FileOutputStream(outputNameFile));

			
			Register tmode = currentProgram.getProgramContext().getRegister("TMode");

			Instruction instruction = getFirstInstruction();
			while (true) {
				if (instruction == null) {
					break;
				}
				if (monitor.isCancelled()) {
					break;
				}
				String InstAddr = instruction.getAddress().toString();
				String ARMorThumb = currentProgram.getProgramContext().getValue(tmode, instruction.getAddress(), false).toString();
				pWriter.println("Inst:"+ARMorThumb+"|Addr:"+InstAddr+"|length:"+instruction.getLength()+"|Disasm:"+instruction.toString());
				instruction = getInstructionAfter(instruction);

			}

			Function function = getFirstFunction();
			int count = 0;
			while (true) {
				if (monitor.isCancelled()) {
					break;
				}
				if (function == null) {
					break;
				}
				int n_p = function.getParameterCount();
			
				boolean ret = function.hasNoReturn();
				pWriter.println("Function:"+function.getEntryPoint().toString()+
						"|ParameterNum:"+n_p+"|ret:"+ret);

				Set<Function> calledFunctionSet = function.getCalledFunctions(getMonitor());
				for (Function calledFunction: calledFunctionSet) {
					pWriter.println("CGEdge:"+function.getEntryPoint()+"->"+calledFunction.getEntryPoint());
				}
				function = getFunctionAfter(function);
				
			}

			pWriter.close();
		} catch (Exception e) {
			StringWriter sw = new StringWriter();
			PrintWriter pw = new PrintWriter(sw);
			e.printStackTrace(pw);
			String sStackTrace = sw.toString();
			println(sStackTrace);
		}

	}

}
