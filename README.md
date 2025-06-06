# KPDB - Windows kernel-mode PDB parser
KPDB is a Windows kernel-mode compatible PDB parser, which can help you parse PDB symbols in a kernel-mode environment. The purpose of this project is to put an end to version-specific hardcoded offsets and signature/instruction scanning so that it will bring more stability to the program. KPDB now not only capable of parsing symbols, but it can also parse the type stream. KPDB is a modified and ported-to-pure-c version of [namazso's lightweight PDB parser](https://gist.github.com/namazso/4bfafdb0233f72f5d13bfee825c203f7), so credit to him.

# Usage
If you want to see what KPDB can do, try cloning the repository, build the project as Release, load the driver, and see the result in DebugView.
![image](https://github.com/user-attachments/assets/4a952455-dcbe-405b-bada-c651be3249f9)

