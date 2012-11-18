#!/usr/bin/env python
#
# $Id$
#
# This program implements GSM milenage algorithm, specified
# in 3GPP TS 55.205, for generating GSM auth triplets. This
# function runs on HLR for providing auth info to SGSN/MME/
# Radius server for UE/MS authentication.
#
# Author: mmehra@juniper.net
#

import sys
import binascii
from   Crypto.Cipher import AES
from   itertools import izip


#Our macro
__XOR__ = lambda x, y: chr(ord(x) ^ ord(y)) 


def LogicalXOR(str1, str2):
    '''Function to XOR two strings'''
    return ''.join(__XOR__(x, y) for (x,y) in izip(str1, str2))


def AESEncrypt(key, buf):
    '''Encrypt buffer using AES-SHA1 128 algorithm
       @key: Key to be used for encryption
       @buf: Buffer to be encrypted'''
    encryptor = AES.new(key, AES.MODE_CBC)
    return encryptor.encrypt(buf)


def GsmMilenageGenOpc(ki, op):
    '''Generate Opc using Ki and Op
       @ki: 128-bit subscriber key
       @op: 128-bit operator variant'''
    opc = AESEncrypt(ki, op)
    return LogicalXOR(opc, op)


def GsmMilenageF2345(ki, opc, rand):
    '''Milenage f2, f3, f4, f5, f5* algorithms'''
    i = 0
    tmp1 = LogicalXOR(rand, opc)
    tmp2 = AESEncrypt(ki, tmp1)
    tmp1 = LogicalXOR(tmp2, opc)
    tmp1 = tmp1[:15] + chr(ord(tmp1[15]) ^ 1)
    tmp3 = AESEncrypt(ki, tmp1)
    tmp3 = LogicalXOR(tmp3, opc)
    res  = tmp3[8:]

    #F3 - to calculate ck
    ck_map = {}
    for i in range(16):
        ck_map[(i+12)%16] = __XOR__(tmp2[i], opc[i])
    ck_map[15] = __XOR__(ck_map[15], chr(2))
    tmp1 = ''.join(val for val in ck_map.values())
    ck = AESEncrypt(ki, tmp1)
    ck = LogicalXOR(ck, opc)

    #F4 - to calculate ik
    ik_map = {}
    for i in range(16):
        ik_map[(i+8)%16] = __XOR__(tmp2[i], opc[i])
    ik_map[15] = __XOR__(ik_map[15], chr(4))
    tmp1 = ''.join(val for val in ik_map.values())
    ik = AESEncrypt(ki, tmp1)
    ik = LogicalXOR(ik, opc)

    return res, ck, ik


def GsmMilenage(ki, opc, rand):
    '''Generate GSM-Milenage (3GPP TS 55.205) auth triplet
       @ki  : 128-bit subscriber key
       @opc : 128-bit operator variant algorithm configuration
       @rand: 128-bit random challenge'''

    res, ck, ik = GsmMilenageF2345(ki, opc, rand)

    #Calculate sres
    sres_map = {}
    for idx in range(4):
        sres_map[idx] = __XOR__(res[idx], res[idx+4])
    sres = ''.join(val for val in sres_map.values())

    #Calculate kc
    kc_map = {}
    for idx in range(8):
        kc_map[idx] = __XOR__(__XOR__(ck[idx], ck[idx+8]),
                              __XOR__(ik[idx], ik[idx+8]))
    kc = ''.join(val for val in kc_map.values())

    return sres, kc


def GenerateAuthTriplets(keyset):
    ki   = binascii.unhexlify(keyset['ki'])
    op   = binascii.unhexlify(keyset['op'])
    rand = binascii.unhexlify(keyset['rand'])

    #Generate opc from ki and op
    opc = GsmMilenageGenOpc(ki, op)

    #Get sres, kc
    sres, kc = GsmMilenage(ki, opc, rand)

    #Store values now
    keyset['opc']  = binascii.hexlify(opc)
    keyset['kc']   = binascii.hexlify(kc)
    keyset['sres'] = binascii.hexlify(sres)
    return


def ReadMilenageInput(filename):
    attribs = []
    keyset  = {}
    try:
       fp = open(filename)
    except:
       print 'Error opening file %s'%(filename)
       sys.exit()

    for line in fp.readlines():
       if line.startswith('#'):
          continue

       if line.startswith('\n'):
          if len(keyset):
             attribs.append(keyset)
             keyset = {}
          continue

       key, value = line.split('=')
       keyset[key] = value.split('\n')[0]

    #Validate input
    if len(attribs) == 0:
       print 'Milenage: Please provide KI/OP/RAND in input file'
       sys.exit()

    for keyset in attribs:
       if not keyset.has_key('ki') or \
          not keyset.has_key('op') or \
          not keyset.has_key('rand'):
          print 'Milenage: KI or OP missing in keyset'
          sys.exit()

    return attribs


def PrintMilenageOutput(attribs):
    '''Prints input read'''
    idx = 1
    for keyset in attribs:
       print 'Keyset # %d'%(idx)
       print '  %2s: %s'%('ki', keyset['ki']) 
       print '  %2s: %s'%('op', keyset['op']) 
       print '  Auth Triplets: '
       print '    %4s: %s'%('rand', keyset['rand']) 
       print '    %4s: %s'%('sres', keyset['sres']) 
       print '    %4s: %s'%('kc',   keyset['kc']) 
       print ''
       idx += 1 
    return
    

def main():
    '''The main function'''
    if len(sys.argv) < 2:
       print 'Milenage: Please provide input file'
       return

    #Read input
    attribs = ReadMilenageInput(sys.argv[1])

    #Generate auth triplets now
    for keyset in attribs:
        GenerateAuthTriplets(keyset)

    #Print output
    PrintMilenageOutput(attribs)
    return


if __name__ == '__main__':
    main()
