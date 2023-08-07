# macrotrace

Simple pin tool to trace execution of the key validation logic for the crackme:  

4d5a9000's EsoLangVM Test
https://crackmes.one/crackme/644d347733c5d43938912cd7

# building and running

Get the latest version of Pin for Linux from:  
https://www.intel.com/content/www/us/en/developer/articles/tool/pin-a-binary-instrumentation-tool-downloads.html

Unzip it somewhere convenient.

Clone this repository directory into **source/tools/macrotrace** inside the directory where you unzipped Pin.

Run **pinconfig.sh** to add Pin's runtime libraries to **/etc/ld.so.conf.d**  
Eg. if you unzipped Pin into **/home/username/pin-3.0-76991-gcc-linux**
```
$ sudo ./pinconfig.sh /home/username/pin-3.0-76991-gcc-linux
```

Alternatively, you can add the paths manually to LD_LIBRARY_PATH, though you will have to redo this each time you restart your shell:
```
$ export PIN=/home/username/pin-3.0-76991-gcc-linux
$ export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$PIN/ia32/runtime/pincrt:$PIN/intel64/runtime/pincrt/:$PIN/extras/xed-ia32/lib/:$PIN/extras/xed-intel64/lib/:$PIN/ia32/lib-ext/:$PIN/intel64/lib-ext/
```

To build, make sure you are in the **macrotrace** directory and run:
```
make TARGET=ia32 
```

To run the trace on the crackme, make sure **keygenme.elf** is executable and run:
```
$ ../../../pin -t obj-ia32/eslv.so -o log.txt -- ./keygenme.elf
```

The program should launch normally, and when you are finished using it, the execution trace should be saved to **log.txt**
