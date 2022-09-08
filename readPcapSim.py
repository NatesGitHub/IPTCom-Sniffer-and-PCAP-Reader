import binascii
import json
import os
import struct

from fileinput import filename
from pathlib import Path
from scapy.all import *
from time import sleep

# Source IP and Port
sipTR = 'x.x.x.x'
sipLF = 'x.x.x.x'
sipSim = 'x.x.x.x'
sport = xxxx
sportSim = xx

prevSeq = None
payLoad = None

flsBuff = None
flsFlag1 = False
flsFlag2 = False
stitchFlag1 = False

index1g = None
index2g = None
nextSeq = None
jsonArr = None

typeArr = []
nameArr = []
outArr = []

binStr = ''


jsonFile = Path(__file__).parent/'flsJson.json'


def handler(packet):
    """
    Handles packet dissection.

    :type packet: bytearray  The packet to handle.
    """
    # Populate type array once to reuse formats.
    if typeArr == []:
        getFastLogSignals(packet)

    dissect(packet)

    #wrpcap('sniffed.pcap', packet, append=True)

    #print(packet.summary())


def loadPcapFile(filePath):
    """
    Load the packet capture file.

    :type filePath: string  The file path of the packet capture file.
    """
    with open (filePath, 'r') as lines:
        for line in lines:
            pcapFile = str(Path(__file__).parent/(line.rstrip('\n')))

            capture = sniff(offline = pcapFile, prn = handler)

            #wrpcap('sniffed.pcap', capture, append=True)


def getFastLogSignals(packet):
    """
    Get the fast log signals from a packet.

    :type packet: bytearray  The packet to get the fast log signals from.
    """
    global flsBuff, flsFlag1, flsFlag2, index1g, index2g, nextSeq, jsonArr, typeArr, nameArr

    if (packet.fields['type'] == 2048) and ((packet.payload.src == sipTR) or (packet.payload.src == sipLF)) and (packet.payload.proto == 6) and ((packet.payload.payload.flags == 'A') or (packet.payload.payload.flags == 'PA')) and (flsFlag2 == False):

        index1 = packet.payload.payload.payload.load.find(b'Signals in Fast Log table')
        index2 = packet.payload.payload.payload.load.find(b'>')
        seq =  packet.payload.payload.seq
        payloadLen = len(packet.payload.payload.payload.load)

        if (index1 != -1) and (index2 != -1) and (flsFlag1 == False):
            flsBuff = packet.payload.payload.payload.load[index1:-17]
            flsFlag2 = True

        elif (index1 != -1) and (index2 == -1) and (flsFlag1 == False):
            flsBuff = packet.payload.payload.payload.load[index1:]
            nextSeq = seq + payloadLen
            index1g = index1
            flsFlag1 = True

        elif (index1 == -1) and (index2 == -1) and (flsFlag1 == True) and (nextSeq == seq):
            flsBuff = flsBuff + packet.payload.payload.payload.load
            nextSeq = seq + payloadLen

        elif (index1 == -1) and (index2 != -1) and (flsFlag1 == True) and (nextSeq == seq):
            flsBuff = flsBuff + packet.payload.payload.payload.load[:-17]
            nextSeq = None
            flsFlag1 = False
            flsFlag2 = True

        if flsFlag2 == True:
            flslist = flsBuff.splitlines()
            jsonArr = json.load(open(jsonFile))

            for f1 in flslist[3:]:
                f2 = f1.split()
                address = str(f2[0], 'utf-8')
                type = str(f2[1], 'utf-8')
                name = str(f2[2], 'utf-8')

                typeArr.append(type)
                nameArr.append(name)

                with open('flsJson.json', 'w') as f3:
                    newflsData = {'Address':address, 'Type':type, 'Name':name}
                    jsonArr['sigFls'].append(newflsData)
                    json.dump(jsonArr, f3, indent = 4)
                    f3.close()

            print ('json file created!')
            print (typeArr)

            # Log header array to text file.
            with open('logs/log1.txt', 'w') as f:
                f.write(f'{str(nameArr)[1:-1]}\n')

            #print(nameArr)

        flsFlag2 = False


def dissect(packet):
    """
    Separate singals from a packet based on the information in its header.

    :type packet: bytearray  The packet to dissect.
    """
    global stitchFlag1, prevSeq, resCntr, payloadPacket, nextSeq, outArr
   
    # Single packet filter -> filter by ipv4, tcp, srcIP, 02ca, 1704, !empty payload.
    if (packet.fields['type'] == 2048) and ((packet.payload.src == sipTR) or (packet.payload.src == sipLF)) and (packet.payload.proto == 6) and (packet.payload.payload.flags == 'PA') and (packet.payload.payload.load[:2] == b'\x02\xca') and (packet.payload.payload.load[7:9] != b'\x00\x00') and (packet.payload.payload.load[-2:] == b'\x17\x04') and (prevSeq != packet.payload.payload.seq):
        
        payloadPacket = packet.payload.payload.load 
       
        iptLen = int((binascii.hexlify(bytes (payloadPacket[2:4])[::-1])), 16)
        sets = int((binascii.hexlify(bytes (payloadPacket[8:10])[::-1])), 16)
        setLen = int((len(payloadPacket[12:-2]))/sets)
        startIndex = 12
        endIndex = startIndex + setLen
        c = 0

        if iptLen == len(payloadPacket):
            #print (payloadPacket)
            while c < sets:
                newPacket = (payloadPacket[startIndex:endIndex])
                #print (newPacket)
                formatData(newPacket, typeArr)
                startIndex += setLen
                endIndex += setLen
                c += 1
                print (outArr) #-> send it somewhere

                # Log signal array to text file.
                logArr(outArr, 'a')

                outArr = []

            print (sets, c)


    # Multi packet filter -> start
    if (packet.fields['type'] == 2048) and ((packet.payload.src == sipTR) or (packet.payload.src == sipLF)) and (packet.payload.proto == 6) and (packet.payload.payload.flags == 'PA') and (packet.payload.payload.load[:2] == b'\x02\xca') and (packet.payload.payload.load[7:9] != b'\x00\x00') and (packet.payload.payload.load[-2:] != b'\x17\x04') and (prevSeq != packet.payload.payload.seq):

        payloadPacket = packet.payload.payload.load
        stitchFlag1 = True

    # Multi packet filter -> middle
    if (packet.fields['type'] == 2048) and ((packet.payload.src == sipTR) or (packet.payload.src == sipLF)) and (packet.payload.proto == 6) and (packet.payload.payload.flags == 'A') and (packet.payload.payload.load[:2] != b'\x02\xca') and (packet.payload.payload.load[-2:] != b'\x17\x04') and (prevSeq != packet.payload.payload.seq) and (stitchFlag1 == True):

        payloadPacket = payloadPacket + packet.payload.payload.load

    # Multi packet filter -> end
    if (packet.fields['type'] == 2048) and ((packet.payload.src == sipTR) or (packet.payload.src == sipLF)) and (packet.payload.proto == 6) and (packet.payload.payload.flags == 'PA') and (packet.payload.payload.load[:2] != b'\x02\xca') and (packet.payload.payload.load[-2:] == b'\x17\x04') and (prevSeq != packet.payload.payload.seq) and (stitchFlag1 == True):

        payloadPacket += packet.payload.payload.load
        stitchFlag1 = False

        iptLen = int((binascii.hexlify(bytes (payloadPacket[2:4])[::-1])), 16)
        sets = int((binascii.hexlify(bytes (payloadPacket[8:10])[::-1])), 16)
        setLen = int((len(payloadPacket[12:-2]))/sets)

        startIndex = 12
        endIndex = startIndex + setLen
        c = 0

        if iptLen == len(payloadPacket):

            while c < sets:
                newPacket = (payloadPacket[startIndex:endIndex])
                formatData(newPacket, typeArr)

                startIndex += setLen
                endIndex += setLen
                c += 1

                print (outArr)

                # Log signal array to text file.
                logArr(outArr, 'a')

                outArr = []

            print(sets, c)


def formatData(packet, arr):
    """
    Format the packet data based on the headers in the array.

    :type packet: bytearray  The packet to format.
    :type arr: array         The array of header information.
    """
    global outArr, binStr

    for item in arr:
        if item == 'B8':
            if binStr == '':
                res = ('{:08b}'.format(int.from_bytes(packet[:1], byteorder = 'big', signed = False)))
                binStr = res
                packet = packet[1:]

            if binStr != '':
                res = int(binStr[-1:])
                outArr.append(res)
                binStr = binStr[:-1]
        else:
            match item:
                case 'U32':
                    res = int.from_bytes(packet[:4], byteorder = 'little', signed = False)
                    packet = packet[4:]

                case 'U16':
                    res = int.from_bytes(packet[:2], byteorder = 'little', signed = False)
                    packet = packet[2:]

                case 'U8':
                    res = int.from_bytes(packet[:1], byteorder = 'little', signed = False)
                    packet = packet[1:]

                case 'I32':
                    res = int.from_bytes(packet[:4], byteorder = 'little', signed = True)
                    packet = packet[4:]

                case 'I16':
                    res = int.from_bytes(packet[:2], byteorder = 'little', signed = True)
                    packet = packet[2:]

                case 'I8':
                    res = int.from_bytes(packet[:1], byteorder = 'little', signed = True)
                    packet = packet[1:]

                case 'F32':
                    [res] = struct.unpack('<f', packet[:4])
                    res = round(res, 2)
                    packet = packet[4:]

            outArr.append(res)

    binStr = ''


fileNumber = 1
newFile = False

def logArr(arr, mode):
    """
    Write a whole array to a text file on one line.

    :type arr: array    The array to write.
    :type mode: string  The mode in which to write (i.e. 'w' as write over them file, or 'a' as append to the file).
    """
    global fileNumber, newFile
    global nameArr

    fileSize = 100000

    with open(('logs/log' + str(fileNumber) + '.txt'), mode) as f:
        # If it is a new file, append the header information to the top.
        if newFile:
            f.write(f'{str(nameArr)[1:-1]}\n')
            newFile = False

        f.write(f'{str(arr)[1:-1]}\n')

        # If file reaches required file size, continue in a new file after appending the header information to the top.
        if int(os.path.getsize('logs/log' + str(fileNumber) + '.txt')) > fileSize:
            fileNumber += 1
            newFile = True


def main():
    # Create a new PCAP file.
    if os.path.exists(Path(__file__).parent/'sniffed.pcap'):
        os.remove(Path(__file__).parent/'sniffed.pcap')

    # Delete the Json file.
    if os.path.exists(Path(__file__).parent/'flsJson.json'):
        os.remove(Path(__file__).parent/'flsJson.json')

    # Create a new Json file.
    open('flsJson.json', 'a').close()
    with open('flsJson.json', 'w') as f:
        json.dump(({'sigFls':[]}), f)

    #capture = sniff(iface ='Ethernet 2', prn=handler) # -> run this for simulation with VM

    loadPcapFile(Path(__file__).parent/'Test/fls.txt') #-> run this for PCAP


if __name__ == '__main__':
    main()
