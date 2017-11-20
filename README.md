# BinSeek
Python写的二进制文件搜索程序，用于纯真IP或phoneloc.dat，在Linux可用Nuitka编译成可执行文件

## Nuitka编译

```bash
nuitka --python-version=2.7 --recurse-all --standalone binseek.py
cp binseek.dist/binseek.exe bin/binseek
cp binseek.dist/libpython2.7.so.1.0 bin/
cp binseek.dist/libpython2.7.so.1.0  bin/
cp binseek.dist/mmap.so  bin/
cp binseek.dist/_bisect.so  bin/
cp binseek.dist/_csv.so  bin/
cp binseek.dist/_functools.so  bin/
cp binseek.dist/_struct.so  bin/
cp /usr/lib64/libc.so.6  bin/
cp /usr/lib64/libdl.so.2  bin/
cp /usr/lib64/libm.so.6  bin/
cp /usr/lib64/libpthread.so.0  bin/
cp /usr/lib64/libutil.so.1  bin/
cp /lib64/ld-linux-x86-64.so.2 /usr/local/lib/
patchelf --set-rpath '$ORIGIN' bin/binseek
patchelf --shrink-rpath bin/binseek
patchelf --set-interpreter "/usr/local/lib/ld-linux-x86-64.so.2" bin/binseek
chmod +x bin/binseek
```

## 使用方法

```bash
python binseek.py ip 183.11.12.34
python binseek.py  phone 1381234
# 或者使用编译好的二进制文件
cd bin/
chmod +x binseek
./binseek ip 183.11.12.34
./binseek phone 1381234
```
