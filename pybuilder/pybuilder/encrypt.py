import ipaddress
from pickle import TRUE
import random
import uuid
from Crypto.Cipher import AES
from ctypes import c_ulong
from ipaddress import ip_address

def RandomKey(KeyLength):
    if KeyLength % 16 != 0 or KeyLength < 0:
        print("Key的长度应为16的倍数。")
        return -1
    source = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    Length = len(source) - 1
    Keys = ""
    for i in range(KeyLength):
        Keys += source[random.randint(0, Length)]
    return Keys.encode("utf-8")

def AesEncrypt(buf, keys, iv):
    # print(len(buf))
    if len(buf)%16 !=0:
        # print("\n[*] length:",len(buf)+(16-(len(buf)%16)))
        addNullbyte = b"\x00" * (16-(len(buf)%16))
        buf += addNullbyte
    aes = AES.new(keys, AES.MODE_CBC, iv) #创建一个aes对象
    # AES.MODE_ECB 表示模式是ECB模式
    return aes.encrypt(buf) #加密明文

def UuidEncode(buf):
    if len(buf)%16 !=0:
        print("\n[*] length:",len(buf)+(16-(len(buf)%16)))
        addNullbyte = b"\x00" * (16-(len(buf)%16))
        buf += addNullbyte
    UuidList = []
    for i in range(len(buf)//16):
        if(len(buf[i*16:i*16+16]) == 0):
            ZeroStr = '0' * len(UuidList[0])
            UuidList.append(ZeroStr)
            break
        b = uuid.UUID(bytes_le=buf[i*16:i*16+16])
        UuidList.append(str(b))
    UuidList.append("0000000000000000000")
    return UuidList

def Ipv4Encode(buf):
    if len(buf) % 4 != 0:
        NullBytes = b"\x00" * (4-(len(buf)%4))
        buf = buf + NullBytes
    buflen = 0
    ipv4List = []
    while buflen < len(buf):
        now4Bytes = buf[buflen:buflen+4]
        ipstr = str(int(now4Bytes[0])) + '.' + str(int(now4Bytes[1])) + '.' + str(int(now4Bytes[2])) + '.' +str(int(now4Bytes[3]))
        ipv4List.append(ipstr)
        buflen += 4
    ipv4List.append("0000000000000000000")
    return ipv4List



def HashEx(buf, len, upper, funchash):
    Hash = c_ulong(funchash)
    for i in range(len):
        character = ord(buf[i])

        if upper:
            if character >= ord('a'):
                character -= 0x20
                
        character = c_ulong(character)
        Hash.value = ((Hash.value << 5) +(Hash.value)) + character.value
    return Hash.value

