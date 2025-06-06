# KPDB - Windows kernel-mode PDB parser
KPDB is a Windows kernel-mode compatible PDB parser, which can help you parse PDB symbols in a kernel-mode environment. The purpose of this project is to put an end to version-specific hardcoded offsets and signature/instruction scanning so that it will bring more stability to the program. KPDB now not only capable of parsing symbols, but it can also parse the type stream. KPDB is a modified and ported-to-pure-c version of [namazso's lightweight PDB parser](https://gist.github.com/namazso/4bfafdb0233f72f5d13bfee825c203f7), so credit to him.

# Usage
If you want to see what KPDB can do, try cloning the repository, build the project as Release, load the driver, and see the result in DebugView.
![image](https://github.com/user-attachments/assets/4a952455-dcbe-405b-bada-c651be3249f9)

# Sponsor
![68747470733a2f2f692e696d6775722e636f6d2f4b454f796445372e706e67](https://github.com/user-attachments/assets/2e0dd6a4-c4e9-48a3-b9c0-4e9d5876c7d6)

WebSec BV, a cybersecurity company based in Amsterdam, is recognized for their dedication to helping businesses and individuals protect themselves against online threats. As a valued sponsor, they have contributed significantly to the promotion of cybersecurity and the creation of a safer online world.

WebSec's team of professionals is committed to staying ahead of the latest threats and developing cutting-edge solutions to keep their clients protected. Their passion for cybersecurity education has made them a trusted and reliable partner in the industry.

Through their sponsorship and support, WebSec has demonstrated their commitment to promoting cybersecurity awareness and helping people stay safe online. Their contributions are greatly appreciated and have made a significant impact on the work being done in this field, such as making this project 'KPDB' a reality.

Overall, WebSec BV is a trusted and respected leader in the fight against cybercrime, and their sponsorship and support have been instrumental in promoting a safer online world. They are a valued partner and their contributions to this important work are truly appreciated.

Website: [websec.nl](websec.nl)

Blog: [websec.nl/blog](websec.nl/blog)
