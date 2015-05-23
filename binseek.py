#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
"""
二进制数据索引文件
"""

import os, os.path
import mmap
import csv
from bisect import bisect
from struct import pack, unpack, calcsize

bin2int = lambda v: int('0x' + v.encode('hex'), 16)

def encode_utf8(word, charset = 'gbk'):
    """ 转换编码为utf-8 """
    encode = lambda w: unicode(w, charset).encode('utf-8')
    try:
        return encode(word)
    except:
        # 当转码失败且最一个字节值为'\x96'，去掉它再解析
        if charset.starswith('gb') and word[-1] == '\x96':
            return encode(word[:-1])
    return ''


class BinWrapper(object):
    """
    二进制文件读写

    +-----------------------+
    +       文件头          +   #索引区第一条(4B) + 索引区最后一条(4B) + 其他内容
    +-----------------------+
    +       记录区          +   #每条记录长度不定，以\0结尾
    +-----------------------+
    +       索引区          +   #每条索引: 索引内容(4B/3B) + 记录偏移量(3B/2B)
    +-----------------------+
    """
    BIN_TYPES = {
        'short' : 'h', 'ushort' : 'H',  #2B
        'int' : 'i', 'uint' : 'I',      #4B
        'long' : 'q', 'ulong' : 'Q',    #8B
        'float' : 'f',                  #4B 
        'double' : 'd',                 #8B
    }
    _fileobj = None
    _filemmp = None
    _index_first = 0   #第一条索引位置，4字节
    _index_last = 0    #最后一条索引位置，4字节
    _index_size = 0
    charset = 'utf-8'   #字符集
    is_bom = False      #索引内容字节序
    term_size = 4       #索引内容定长
    offset_size = 3     #偏移量定长

    def __init__(self, filename, readonly = True):
        filemode = 'rb' if readonly else 'w+b'
        self._fileobj = open(filename, filemode)

    def __del__(self):
        if self._filemmp:
            self._filemmp.close()
        self._fileobj.close()

    def format(self, target):
        raise NotImplementedError
        
    @classmethod
    def calc_pad_size(cls, name = 'uint', size = False):
        fmt = cls.BIN_TYPES.get(name, 'I')
        if not size:
            size = calcsize(fmt)
            pad_size = 0
        else:
            pad_size = calcsize(fmt) - size
        return fmt, size, pad_size

    @property
    def index_size(self):
        """ 单条索引定长，必须大于0 """
        if not self._index_size:
            self._index_size = self.term_size + self.offset_size
        return self._index_size

    def pack_number(self, value, name = 'uint', size = False, is_bom = False):
        fmt, size, pad_size = self.__class__.calc_pad_size(name, size)
        pre, left, right = '', None, None
        if pad_size > 0:
            if is_bom:
                pre = '>'
                left = pad_size
            else:
                pre = '<'
                right = - pad_size
        value = pack(pre + fmt, int(value))
        return value[left:right]

    def pack_string(self, value):
        if self.charset.lower() != 'utf-8':
            if not isinstance(value, unicode):
                value = unicode(value, 'utf-8')
            value = value.encode(self.charset)
        return value + '\0'
    
    
class ReaderMixin:
    _index_offset = 0 #第一条索引离文件头的距离，这里的文件可能是mmap内存文件

    def read_header(self):
        try:
            self._fileobj.seek(0, os.SEEK_SET)
            self._index_first = self.read_number('uint')
            self._index_last = self.read_number('uint')
        except:
            pass
        self._index_offset = self._index_first
        return self
        
    def mmap_file(self):
        if not self._index_first:
            self.read_header() #需要先读取索引区位置
        if mmap.ALLOCATIONGRANULARITY > 0:
            self._index_offset = self._index_first % mmap.ALLOCATIONGRANULARITY
        fno = self._fileobj.fileno()
        length = len(self) * self.index_size + self._index_offset
        offset = self._index_first - self._index_offset
        self._filemmp = mmap.mmap(fno, length, access = 1, offset = offset)
        return self

    def __len__(self):
        bytes = self._index_last - self._index_first
        return bytes / self.index_size + 1

    def __getitem__(self, idx):
        offset = idx * self.index_size
        if self._filemmp:
            fileobj = self._filemmp
        else:
            fileobj = self._fileobj
        fileobj.seek(offset + self._index_offset, os.SEEK_SET)
        return self.read_bin(size = self.term_size, 
                    fileobj = fileobj, reverse = not self.is_bom)

    def bisect_offset(self, target):
        """ 二分法查找索引区 """
        idx = bisect(self, target) - 1
        offset = idx * self.index_size + self.term_size
        if self._filemmp:
            fileobj = self._filemmp
        else:
            fileobj = self._fileobj
        fileobj.seek(offset + self._index_offset, os.SEEK_SET)
        return self.read_number('uint', size = self.offset_size, fileobj = fileobj)
    
    def read_bin(self, size = 1, fileobj = None, reverse = False):
        if not fileobj:
            fileobj = self._fileobj
        value = fileobj.read(size)
        if size != len(value):
            raise EOFError
        if reverse and len(value) > 1:
            value = value[::-1]
        return value

    def read_number(self, name = 'uint', size = False, is_bom = False, fileobj = None):
        fmt, size, pad_size = self.__class__.calc_pad_size(name, size)
        value = self.read_bin(size = size, fileobj = fileobj)
        pre = ''
        if pad_size > 0:
            if is_bom:
                pre = '>'
                value = '\0' * pad_size + value
            else:
                pre = '<'
                value += '\0' * pad_size
        return unpack(pre + fmt, value)[0]
        

    def read_string(self, value = ''):
        """ 一个接一个读取字符，直到\0，不受字节序影响 """
        while True:
            c = self._fileobj.read(1)
            if c == '\0':
                break
            else:
                value += c
        if self.charset.lower() != 'utf-8':
            value = encode_utf8(value, self.charset)
        return value

    def read_record(self, target):
        return self.read_string()

    def lookup(self, target):
        """ 读取最符合的记录 """
        if not self._index_first:
            self.read_header() #需要先读取索引区位置
        target = self.format(target)
        offset = self.bisect_offset(target)
        self._fileobj.seek(offset, os.SEEK_SET)
        return self.read_record(target)
        
        
class WriterMixin:
    _index_list = []
    
    @staticmethod
    def read_source(delimiter = ',', quotechar = '"', charset = 'utf-8', 
                    ignore_rows = 0, ignore_cols = 0, read_cols = 0):
        with open(source, 'rb') as fh:
            csv_reader = csv.reader(fh, delimiter=delimiter, quotechar=quotechar)
            for i, row in enumerate(csv_reader):
                if i < ignore_rows:
                    continue
                if len(row) <= 1:
                    continue
                left = ignore_cols + 1
                right = left + read_cols if read_cols > 0 else None
                record = delimiter.join(row[left:right])
                if charset != 'utf-8':
                    record = encode_utf8(record, charset)
                yield row[ignore_cols], record

    def pack_header(self, addition = None):
        result = ''
        result += self.pack_number(self._index_first, 'uint')
        result += self.pack_number(self._index_last, 'uint')
        if addition:
            result += self.pack_string(addition)
        return result

    def write_bin(self, value, reverse = False):
        if reverse and len(value) > 1:
            value = value[::-1]
        pos = self._fileobj.tell()
        self._fileobj.write(value)
        return pos

    def pack_index(self, index, is_bom = True):
        """ 保持高位在前 """
        return self.pack_number(index, 'uint', self.term_size, is_bom = is_bom)

    def write_record(self, index, record, **kwargs):
        pos = self.write_bin(self.pack_string(record))
        value = self.pack_index(index, is_bom = self.is_bom)
        value += self.pack_number(pos, 'uint', self.offset_size)
        self._index_list.append(value)

    def build(self, source, version = '', **kwargs):
        """ 从CSV文件中构建二进制文件 """
        self.write_bin(self.pack_header(version))
        records = [row for row in WriterMixin.read_source(**kwargs)]
        records.sort()
        for index, record in records:
            self.write_record(index, record, **kwargs)
        self._index_first = self._fileobj.tell()
        self.write_bin(''.join(self._index_list))
        self._index_last = self._fileobj.tell() - self.index_size
        self._fileobj.seek(0, os.SEEK_SET)
        self.write_bin(self.pack_header())


class IPLocation(BinWrapper, ReaderMixin):
    """ IP真实地址 """
    BYTE_FLAG = 1            #标志位长度，1字节
    FLAG_TERMINATE = 0       #终止，也不在当前位置读取
    FLAG_JUMP_FIRST = 1      #首次跳转
    FLAG_JUMP_SENIOR = 2     #高级跳转
    charset = 'gbk'          #字符集

    def format(self, target):
        """ 格式化IP地址 """
        pieces = target.strip().split('.')
        target = bytearray([int(p) for p in pieces])
        return str(target)

    def read_record(self, target):
        tail = self.read_bin(size = self.term_size, reverse = not self.is_bom) #IP结尾
        if target <= tail:
            return self.read_zone()
        else:
            return '', ''

    def read_zone(self):
        """
        读取分区，根据标志位1/2跳转或再次跳转
        * 都在当前
        2 分区跳转、位置当前
        1* 分区跳转、位置当前（已跳转）
        12 分区再跳转、位置当前（已跳转）
        """
        flag = ord(self.read_bin(size = 1))
        if flag == self.FLAG_JUMP_FIRST:
            offset = self.read_number('uint', size = self.offset_size)
            self._fileobj.seek(offset, os.SEEK_SET)
            return self.read_zone()
        elif flag == self.FLAG_JUMP_SENIOR: #仅分区跳转
            offset = self.read_number('uint', size = self.offset_size)
            addr = self.read_address()
            self._fileobj.seek(offset, os.SEEK_SET)
            zone = self.read_string()
        else: #在当前位置读取
            zone = self.read_string(chr(flag))
            addr = self.read_address()
        return zone.strip(), addr.strip()

    def read_address(self):
        """ 读取位置，根据标志位0/1/2跳转 """
        flag = ord(self.read_bin(size = 1))
        if flag == self.FLAG_TERMINATE:
            return '' #没有可读数据，返回空字符串
        elif flag == self.FLAG_JUMP_FIRST \
                or flag == self.FLAG_JUMP_SENIOR: #重定向后读取
            offset = self.read_number('uint', size = self.offset_size)
            self._fileobj.seek(offset, os.SEEK_SET)
            return self.read_string()
        else: #在当前位置读取
            return self.read_string(chr(flag))


class IPNation(BinWrapper, ReaderMixin, WriterMixin):
    """ IP所在国度 """
    term_size = 4       #索引内容定长
    offset_size = 2     #偏移量定长

    def format(self, target):
        """ 格式化IP地址 """
        pieces = target.strip().split('.')
        target = bytearray([int(p) for p in pieces])
        return str(target)

    def read_record(self, target):
        tail = self.read_bin(size = self.term_size, reverse = not self.is_bom) #IP结尾
        if target <= tail:
            return self.read_string()
        else:
            return ''

    def write_record(self, index, record, delimiter = '\t'):
        tail, record = record.split(delimiter, 1)
        self.write_bin(tail, reverse = not self.is_bom)
        pos = self.write_bin(self.pack_string(record))
        value = self.pack_index(index, is_bom = self.is_bom)
        value += self.pack_number(pos, 'uint', self.offset_size)
        self._index_list.append(value)


class PhoneLoc(BinWrapper, ReaderMixin, WriterMixin):
    """ 手机归属地 """
    is_bom = True       #索引内容字节序
    term_size = 3       #索引内容定长
    offset_size = 3     #偏移量定长

    def format(self, target):
        """ 格式化电话号码，国际区号保留，中国大陆区号去除 """
        target = target.strip().replace('+', '00')
        #去0后取前7位
        if target.startswith('00'):
            target = target.lstrip('0')
        if len(target) > 7:
            target = target[:7]
        return self.pack_index(target, is_bom = True)


if __name__ == '__main__':
    import sys
    if len(sys.argv) > 2:
        act = sys.argv[1].lower()
        if act == 'ip':
            filename = 'qqwry.dat'
            loc = IPLocation(filename, readonly = True).mmap_file()
            for ip in sys.argv[2:]:
                zone, addr = loc.lookup(ip)
                print ip, zone, addr
        elif act == 'phone':
            filename = 'phoneloc.dat'
            source = 'mobile.txt'
            if not os.path.exists(filename):
                loc = PhoneLoc(filename, readonly = False)
                loc.build(source, version = '15.5.11', delimiter='\t',
                        charset = 'gbk', ignore_cols = 1, read_cols = 3)
            else:
                loc = PhoneLoc(filename, readonly = True)
            loc.mmap_file()
            for phone in sys.argv[2:]:
                addr = loc.lookup(phone)
                print phone, addr
