# KPDB - Windows kernel-mode PDB parser
KPDB is a Windows kernel-mode compatible PDB parser, it can help you parses PDB symbols in the kernel-mode environment. The purpose of this project is to put an end to version-specific hardcoded offsets and signature/instruction scanning so that it will bring more stability to the program. At the moment, KPDB only supports parsing symbols, but I will add type parsing capability on the next release. KPDB is a modified and ported-to-pure-c version of [namazso's lightweight PDB parser](https://gist.github.com/namazso/4bfafdb0233f72f5d13bfee825c203f7), so credit to him.

# Usage
If you want to see what KPDB can do, try cloning the repository, build the project as Release, load the driver, and see the result in DebugView.
![image](https://user-images.githubusercontent.com/41237415/209555217-0bcec534-8eb4-4aa7-960a-34cf30475f88.png)
