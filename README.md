# An Empirical Study on ARM Disassembly Tools
This is the repository for paper "An Empirical Study on ARM Disassembly Tools" accepted to ISSTA 2020


# Tools
We evaluate eight different disassembly tools. They are 
- [angr (version 8.19.4.5)](https://angr.io/) 
- [BAP (version 1.6.0)](https://github.comBinaryAnalysisPlatform/bap)
- [Objdump (version 2.30)](https://linux.die.net/man/1/objdump)
- [Ghidra (version 9.0.4)](https://ghidra-sre.org/)
- [Radare2 (version 3.6.0)](https://www.radare.org/n/radare2.html)
- [Binary Ninja (version 1.1.1470)](https://binary.ninja/) 
- [Hopper (version 4.5.13)](https://www.hopperapp.com/)
- [IDA Pro (version 7.3)](https://www.hex-rays.com/products/ida/)

Each tool has different method to extract the disassembly result. We read the manual carefully and write a script for each tool to extract the disassembly result. The detail script are listed in [Adapters](https://github.com/valour01/arm_disasssembler_study/tree/master/adapter).  The code of evaluating the efficiency of different tools are also integrated into the adapters of each tool.

# Dataset 
[Dataset](https://connectpolyu-my.sharepoint.com/:u:/g/personal/16900820r_connect_polyu_hk/ES7bXmDsLBBPvQaa_dIyZ_wB2CYoMFEYfIsnONJpNbZUdw?e=udRGIDt) contains the dataset we used in our experiments. However, due to the licensing issues, we cannot share the binaries compiled from [SPEC CPU® 2006](https://www.spec.org/cpu2006/) directly.

You can take the following tips to build the SPEC CPU 2006 by yourselves. Feel free if you have any questions. 

- Prepare the [SPEC CPU® 2006](https://www.spec.org/cpu2006/)
- Install SPEC CPU® 2006 by following the [documentation](https://www.spec.org/cpu2006/Docs/install-guide-unix.html)
- I provided two template configuration files (i.e., [clang.cfg](https://github.com/valour01/arm_disasssembler_study/blob/master/spec2006/clang.cfg) and [gcc.cfg](https://github.com/valour01/arm_disasssembler_study/blob/master/spec2006/gcc.cfg)) for GCC and Clang, respectively. You can change the configuration files for different compiling options.
- Use the command `runspec --config=/path/to/config/gcc.cfg --action=build --rebuild --tune=base binary name` to build every single binary.
- You can glue all of them with your own python or shell script.



# Ground Truth
[truth.py](https://github.com/valour01/arm_disasssembler_study/blob/master/truth.py) is the file to extract the ground truth from a binary with debugging information.


# Citation
If you use the related script, dataset or the insights we observed in our paper. Please considering cite our paper.

```
@inproceedings{10.1145/3395363.3397377,
author = {Jiang, Muhui and Zhou, Yajin and Luo, Xiapu and Wang, Ruoyu and Liu, Yang and Ren, Kui},
title = {An Empirical Study on ARM Disassembly Tools},
year = {2020},
isbn = {9781450380089},
publisher = {Association for Computing Machinery},
address = {New York, NY, USA},
url = {https://doi.org/10.1145/3395363.3397377},
doi = {10.1145/3395363.3397377},
booktitle = {Proceedings of the 29th ACM SIGSOFT International Symposium on Software Testing and Analysis},
pages = {401–414},
numpages = {14},
keywords = {Empirical Study, Disassembly Tools, ARM Architecture},
location = {Virtual Event, USA},
series = {ISSTA 2020}
}
```
