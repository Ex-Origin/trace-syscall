
# Trace SYScall

Trace SYScall to reach the expected requirements.

It is only supported for Linux.

## Compile

```shell
gcc -g -D TRACE_WRITE   main.c -o trace_write
gcc -g -D TRACE_READ    main.c -o trace_read
gcc -g -D TRACE_EXECVE  main.c -o trace_execve
```

## Trace Write

Trace `SYS_write` and `SYS_wirtev` to show the files that are being written by the specified application. 

```shell
$ gcc -g -D TRACE_WRITE   main.c -o trace_write
$ trace_write
Usage: ./trace_write command
$ ./trace_write pip install requests
[TRACE INFO]: pipe:[508966]
[TRACE INFO]: pipe:[503529]
[TRACE INFO]: /dev/null
[TRACE INFO]: pipe:[503526]
[TRACE INFO]: pipe:[508968]
[TRACE INFO]: /tmp/4vw85v75
[TRACE INFO]: socket:[508975]
[TRACE INFO]: /root/.cache/pip/http/e/a/c/6/1/eac61126daf80149d2a016f12a54eab5e3b5c1dbc77410ff1a97edc4okrq1ute.tmp
[TRACE INFO]: /dev/pts/2
Collecting requests
[TRACE INFO]: socket:[508977]
  Downloading requests-2.27.1-py2.py3-none-any.whl (63 kB)
[TRACE INFO]: /tmp/pip-unpack-8qb0r_s9/requests-2.27.1-py2.py3-none-any.whl
     |███████████████████████████████▏| 61 kB 182 kB/s eta 0:00:01[TRACE INFO]: /root/.cache/pip/http/7/4/4/4/0/7444028c92844801309674fa32b7e7e4cedf52a841b159c3a0c5c614872p4s2f.tmp
     |████████████████████████████████| 63 kB 175 kB/s            
[TRACE INFO]: /tmp/pip-req-tracker-tda92i_f/7444028c92844801309674fa32b7e7e4cedf52a841b159c3a0c5c614
Requirement already satisfied: certifi>=2017.4.17 in /usr/lib/python3/dist-packages (from requests) (2019.11.28)
Requirement already satisfied: urllib3<1.27,>=1.21.1 in /usr/lib/python3/dist-packages (from requests) (1.25.8)
[TRACE INFO]: /root/.cache/pip/http/5/b/d/8/9/5bd894eeb3dfe1c8aaee1daecdfb74bbb314293813a730238621f077_rveqaj7.tmp
Collecting charset-normalizer~=2.0.0
  Downloading charset_normalizer-2.0.12-py3-none-any.whl (39 kB)
[TRACE INFO]: /tmp/pip-unpack-u64f27m4/charset_normalizer-2.0.12-py3-none-any.whl
[TRACE INFO]: /root/.cache/pip/http/7/b/e/7/0/7be70c2367d09448b3057000aeeba81fbe2b757c84f8f2d4d928f49cfpq9hpl7.tmp
[TRACE INFO]: /tmp/pip-req-tracker-tda92i_f/7be70c2367d09448b3057000aeeba81fbe2b757c84f8f2d4d928f49c
Requirement already satisfied: idna<4,>=2.5 in /usr/lib/python3/dist-packages (from requests) (2.8)
Installing collected packages: charset-normalizer, requests
[TRACE INFO]: /usr/local/lib/python3.8/dist-packages/charset_normalizer/__init__.py
[TRACE INFO]: /usr/local/lib/python3.8/dist-packages/charset_normalizer/api.py
[TRACE INFO]: /usr/local/lib/python3.8/dist-packages/charset_normalizer/cd.py
[TRACE INFO]: /usr/local/lib/python3.8/dist-packages/charset_normalizer/constant.py
...
[TRACE INFO]: /usr/local/lib/python3.8/dist-packages/requests/__pycache__/structures.cpython-38.pyc.139768695870208
[TRACE INFO]: /usr/local/lib/python3.8/dist-packages/requests/__pycache__/utils.cpython-38.pyc.139768697467360
[TRACE INFO]: /usr/local/lib/python3.8/dist-packages/requests-2.27.1.dist-info/INSTALLER1ao0qzaa.tmp
[TRACE INFO]: /usr/local/lib/python3.8/dist-packages/requests-2.27.1.dist-info/RECORDe5jz3x93.tmp
Successfully installed charset-normalizer-2.0.12 requests-2.27.1
```

## Trace Read

Trace `SYS_read` and `SYS_readv` to show the files that are being read by the specified application. 

```shell
$ gcc -g -D TRACE_READ    main.c -o trace_read
$ ./trace_read
Usage: ./trace_read command
$ ./trace_read useradd trace
[TRACE INFO]: /usr/lib/libaudit.so.1.0.0
[TRACE INFO]: /usr/lib/libacl.so.1.1.2301
[TRACE INFO]: /usr/lib/libattr.so.1.1.2501
[TRACE INFO]: /usr/lib/libdl-2.33.so
[TRACE INFO]: /usr/lib/libc-2.33.so
[TRACE INFO]: /usr/lib/libcap-ng.so.0.0.0
[TRACE INFO]: /proc/sys/kernel/cap_last_cap
[TRACE INFO]: /proc/sys/kernel/ngroups_max
[TRACE INFO]: /etc/login.defs
[TRACE INFO]: /etc/default/useradd
[TRACE INFO]: /etc/nsswitch.conf
[TRACE INFO]: /usr/lib/libnss_files-2.33.so
[TRACE INFO]: /etc/group
[TRACE INFO]: /usr/lib/libnss_systemd.so.2
[TRACE INFO]: /usr/lib/librt-2.33.so
[TRACE INFO]: /usr/lib/libm-2.33.so
[TRACE INFO]: /usr/lib/libcrypt.so.2.0.0
[TRACE INFO]: /usr/lib/libcrypto.so.1.1
[TRACE INFO]: /usr/lib/libp11-kit.so.0.3.0
[TRACE INFO]: /usr/lib/libgcc_s.so.1
[TRACE INFO]: /usr/lib/libpthread-2.33.so
[TRACE INFO]: /usr/lib/libffi.so.8.1.0
[TRACE INFO]: /proc/sys/kernel/random/boot_id
[TRACE INFO]: /etc/passwd
[TRACE INFO]: /etc/gshadow
[TRACE INFO]: /etc/shadow
[TRACE INFO]: /usr/share/zoneinfo/Asia/Shanghai
```

## Trace Execve

Trace `SYS_execve` to show the command that are being executed by the specified application. 

```shell
$ gcc -g -D TRACE_EXECVE  main.c -o trace_execve
$ ./trace_execve
Usage: ./trace_execve command
$ ./trace_execve gcc -g -D TRACE_EXECVE  main.c -o trace_execve2
[TRACE INFO]: /usr/bin/gcc -g -D TRACE_EXECVE main.c -o trace_execve2
[TRACE INFO]: /usr/lib/gcc/x86_64-pc-linux-gnu/11.1.0/cc1 -quiet -D TRACE_EXECVE main.c -quiet -dumpdir trace_execve2- -dumpbase main.c -dumpbase-ext .c -mtune=generic -march=x86-64 -g -o /tmp/cchVCsia.s
[TRACE INFO]: /usr/local/bin/as --gdwarf-5 --64 -o /tmp/cc1c9jzt.o /tmp/cchVCsia.s
[TRACE INFO]: /usr/bin/as --gdwarf-5 --64 -o /tmp/cc1c9jzt.o /tmp/cchVCsia.s
[TRACE INFO]: /usr/lib/gcc/x86_64-pc-linux-gnu/11.1.0/collect2 -plugin /usr/lib/gcc/x86_64-pc-linux-gnu/11.1.0/liblto_plugin.so -plugin-opt=/usr/lib/gcc/x86_64-pc-linux-gnu/11.1.0/lto-wrapper -plugin-opt=-fresolution=/tmp/ccZGZTqG.res -plugin-opt=-pass-through=-lgcc -plugin-opt=-pass-through=-lgcc_s -plugin-opt=-pass-through=-lc -plugin-opt=-pass-through=-lgcc -plugin-opt=-pass-through=-lgcc_s --build-id --eh-frame-hdr --hash-style=gnu -m elf_x86_64 -dynamic-linker /lib64/ld-linux-x86-64.so.2 -pie -o trace_execve2 /usr/lib/gcc/x86_64-pc-linux-gnu/11.1.0/../../../../lib/Scrt1.o /usr/lib/gcc/x86_64-pc-linux-gnu/11.1.0/../../../../lib/crti.o /usr/lib/gcc/x86_64-pc-linux-gnu/11.1.0/crtbeginS.o -L/usr/lib/gcc/x86_64-pc-linux-gnu/11.1.0 -L/usr/lib/gcc/x86_64-pc-linux-gnu/11.1.0/../../../../lib -L/lib/../lib -L/usr/lib/../lib -L/usr/lib/gcc/x86_64-pc-linux-gnu/11.1.0/../../.. /tmp/cc1c9jzt.o -lgcc --push-state --as-needed -lgcc_s --pop-state -lc -lgcc --push-state --as-needed -lgcc_s --pop-state /usr/lib/gcc/x86_64-pc-linux-gnu/11.1.0/crtendS.o /usr/lib/gcc/x86_64-pc-linux-gnu/11.1.0/../../../../lib/crtn.o
[TRACE INFO]: /usr/bin/ld -plugin /usr/lib/gcc/x86_64-pc-linux-gnu/11.1.0/liblto_plugin.so -plugin-opt=/usr/lib/gcc/x86_64-pc-linux-gnu/11.1.0/lto-wrapper -plugin-opt=-fresolution=/tmp/ccZGZTqG.res -plugin-opt=-pass-through=-lgcc -plugin-opt=-pass-through=-lgcc_s -plugin-opt=-pass-through=-lc -plugin-opt=-pass-through=-lgcc -plugin-opt=-pass-through=-lgcc_s --build-id --eh-frame-hdr --hash-style=gnu -m elf_x86_64 -dynamic-linker /lib64/ld-linux-x86-64.so.2 -pie -o trace_execve2 /usr/lib/gcc/x86_64-pc-linux-gnu/11.1.0/../../../../lib/Scrt1.o /usr/lib/gcc/x86_64-pc-linux-gnu/11.1.0/../../../../lib/crti.o /usr/lib/gcc/x86_64-pc-linux-gnu/11.1.0/crtbeginS.o -L/usr/lib/gcc/x86_64-pc-linux-gnu/11.1.0 -L/usr/lib/gcc/x86_64-pc-linux-gnu/11.1.0/../../../../lib -L/lib/../lib -L/usr/lib/../lib -L/usr/lib/gcc/x86_64-pc-linux-gnu/11.1.0/../../.. /tmp/cc1c9jzt.o -lgcc --push-state --as-needed -lgcc_s --pop-state -lc -lgcc --push-state --as-needed -lgcc_s --pop-state /usr/lib/gcc/x86_64-pc-linux-gnu/11.1.0/crtendS.o /usr/lib/gcc/x86_64-pc-linux-gnu/11.1.0/../../../../lib/crtn.o
```


