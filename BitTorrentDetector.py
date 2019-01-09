#!/usr/bin/env python

import argparse
import sys
import os.path
import re
import netaddr
import dpkt
import socket
import operator
import collections
import urllib
import json
import xml.etree.ElementTree as ET
from xml.dom import minidom


flow = {}
suspects = {}
convinced = {}
info_hashes = []
wasConvinced = False
enableSuspects = False
network = None
mask = (0xFFFFFFFF)

debugConvinced = 0
debugSuspected = 0
debugConvincedTCPPorts = 0
debugConvincedUDPPorts = 0
debugSuspectedTCPPorts = 0
debugSuspectedUDPPorts = 0
debugInfoHashes = 0


class arguments:
    def __init__(self):
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument('-f', action="store", dest="file")
        self.parser.add_argument('-o', action="store", dest="outputfile")
        self.parser.add_argument('-s', action="store_true")
        self.parser.add_argument('-n', action="store", dest="network")
        self.parser.add_argument('-d', action="store_true", dest="debug")
        self.results = self.parser.parse_args()
    def getFile(self):
        return self.results.file
    def getOutputFile(self):
        return self.results.outputfile
    def getEnableSuspects(self):
        return self.results.s
    def getDebug(self):
        return self.results.debug
    def getNetwork(self):
        global mask
        if(self.results.network == None):
            return None
        result = re.search(r"([\d+\.]+)\/(\d+)", self.results.network)
        if(result != None):
            mask = mask >> 32 - int(result.group(2))
            mask = mask << 32 - int(result.group(2))
            return(int(netaddr.IPAddress(result.group(1))))


class packetClass:
    def __init__(self):
        self.protocol = 0
        self.src = 0
        self.dst = 0
        self.sport = 0
        self.dport = 0
        self.payload = 0
        self.length = 0
    def decodePacket(self, packet):
        try:
            eth=dpkt.ethernet.Ethernet(packet)
        except:
            self.protocol=0
            return
        try:
            ip=eth.data
        except:
            self.protocol=0
            return
        try:
            trans=ip.data
        except:
            self.protocol=0
            return
        if(isinstance(trans, dpkt.tcp.TCP)):
            self.protocol = 1
        elif(isinstance(trans, dpkt.udp.UDP)):
            self.protocol = 2
        else:
            self.protocol = 0
            return
        try:
            self.src = int(netaddr.IPAddress(socket.inet_ntop(socket.AF_INET, ip.src)))
            self.dst = int(netaddr.IPAddress(socket.inet_ntop(socket.AF_INET, ip.dst)))
        except:
            try:
                self.src = socket.inet_ntop(socket.AF_INET6, ip.src)
                self.dst = socket.inet_ntop(socket.AF_INET6, ip.dst)
            except:
                self.protocol = 0
        self.length = len(eth)
        self.sport = trans.sport
        self.dport = trans.dport
        self.payload = trans.data
    def getSport(self):
        return self.sport
    def getDport(self):
        return self.dport
    def getSrc(self):
        return self.src
    def getDst(self):
        return self.dst
    def getProtocol(self):
        return self.protocol
    def getPayload(self):
        return self.payload
    def getLength(self):
        return self.length
    def destroyPacket(self):
        self.protocol = 0
        self.src = 0
        self.dst = 0
        self.sport = 0
        self.dport = 0
        self.payload = 0
        self.length = 0

def testTrackerCommunication(packet):
    global wasConvinced
    global flow
    global convinced
    global suspects
    if(len(packet.getPayload()) == 0):
        return
    result = re.search(r"GET \/announce\?", packet.getPayload(), re.IGNORECASE)
    if(result != None):
        wasConvinced = True
        result = re.search(r"info_hash\=([^&]+)", packet.getPayload(), re.IGNORECASE)
        if(result != None):
            info_hash = stringifyInfoHash(urllib.unquote(result.group(1)))
            if(info_hash not in info_hashes):
                info_hashes.append(info_hash)
            result = re.search(r"port\=(\d+)", packet.getPayload(), re.IGNORECASE)
            if(result != None):
                srcAddress = packet.getSrc()
                if srcAddress not in convinced:
                    convinced[srcAddress] = {}
                    convinced[srcAddress][1] = []
                    convinced[srcAddress][2] = []
                    convinced[srcAddress][1].append(int(result.group(1)))
                    convinced[srcAddress][2].append(int(result.group(1)))
                    wasConvinced = True
                else:
                    if int(result.group(1)) not in convinced[srcAddress][1]:
                        convinced[srcAddress][1].append(int(result.group(1)))
                        wasConvinced = True
                    if int(result.group(1)) not in convinced[srcAddress][2]:
                        convinced[srcAddress][2].append(int(result.group(1)))
                        wasConvinced = True
    else:
        result = re.search(r"GET \/scrape\?", packet.getPayload(), re.IGNORECASE)
        if(result != None):
            wasConvinced = True
            result = re.search(r"info_hash\=([^\ \&]+)", packet.getPayload(), re.IGNORECASE)
            if(result != None):
                info_hash = stringifyInfoHash(urllib.unquote(result.group(1)))
                if(info_hash not in info_hashes):
                    info_hashes.append(info_hash)
                wasConvinced = True

def testPeerCommunication(packet):
    global wasConvinced
    global flow
    global convinced
    global suspects
    payload = packet.getPayload()
    protocol = packet.getProtocol()
    if(len(packet.getPayload()) < 20):
        return
    if(protocol == 1):
        if(ord(payload[0]) != 19):
            return
    if(protocol == 2):
        if(ord(payload[20]) != 19):
            return
    result = re.search(r"BitTorrent Protocol", payload, re.IGNORECASE)
    if result != None:
        wasConvinced = True
        if(packet.getProtocol() == 1):
            info_hash = payload[28:48]
            info_hash = stringifyInfoHash(info_hash)
            if(info_hash not in info_hashes):
                info_hashes.append(info_hash)
        if(packet.getProtocol() == 2):
            info_hash = payload[48:68]
            info_hash = stringifyInfoHash(info_hash)
            if(info_hash not in info_hashes):
                info_hashes.append(info_hash)
        srcAddress = packet.getSrc()
        dstAddress = packet.getDst()
        sport = packet.getSport()
        dport = packet.getDport()
        if srcAddress not in convinced:
            convinced[srcAddress] = {}
            convinced[srcAddress][1] = []
            convinced[srcAddress][2] = []
            convinced[srcAddress][protocol].append(sport)
            wasConvinced = True
        else:
            if sport not in convinced[srcAddress][protocol]:
                convinced[srcAddress][protocol].append(sport)
                wasConvinced = True
        
        if dstAddress not in convinced:
            convinced[dstAddress] = {}
            convinced[dstAddress][1] = []
            convinced[dstAddress][2] = []
            convinced[dstAddress][protocol].append(dport)
            wasConvinced = True
        else:
            if dport not in convinced[dstAddress][protocol]:
                convinced[dstAddress][protocol].append(dport)
                wasConvinced = True

def flowAnalyser(packet):
    global wasConvinced
    global flow
    global convinced
    global suspects
    sport = packet.getSport()
    dport = packet.getDport()
    if (sport < 1024 or dport < 1024):
        return
    srcAddress = packet.getSrc()
    dstAddress = packet.getDst()
    protocol = packet.getProtocol()
    if((sport >= 6881 and sport <= 6999) or (dport >= 6881 and dport <= 6999)):
        if(srcAddress not in suspects):                
            suspects[srcAddress] = {}
            suspects[srcAddress][1] = []
            suspects[srcAddress][2] = []
            suspects[srcAddress][protocol].append(sport)
        elif (sport not in suspects[srcAddress][protocol]):
            suspects[srcAddress][protocol].append(sport)
        if(dstAddress not in suspects):                
            suspects[dstAddress] = {}
            suspects[dstAddress][1] = []
            suspects[dstAddress][2] = []
            suspects[dstAddress][protocol].append(dport)
        elif (dport not in suspects[dstAddress][protocol]):
            suspects[dstAddress][protocol].append(dport)
        return
    if(srcAddress in convinced or dstAddress in convinced):
        if(srcAddress not in suspects):                
            suspects[srcAddress] = {}
            suspects[srcAddress][1] = []
            suspects[srcAddress][2] = []
            suspects[srcAddress][protocol].append(sport)
        elif (sport not in suspects[srcAddress][protocol]):
            suspects[srcAddress][protocol].append(sport)
        if(dstAddress not in suspects):                
            suspects[dstAddress] = {}
            suspects[dstAddress][1] = []
            suspects[dstAddress][2] = []
            suspects[dstAddress][protocol].append(dport)
        elif (dport not in suspects[dstAddress][protocol]):
            suspects[dstAddress][protocol].append(dport)
        return
    """----------------------------------------------------"""
    if(srcAddress not in flow):
        flow[srcAddress] = {}
        flow[srcAddress][1] = {}
        flow[srcAddress][2] = {}
        flow[srcAddress][protocol][sport] = {}
        flow[srcAddress][protocol][sport][dstAddress] = []
        flow[srcAddress][protocol][sport][dstAddress].append(dport)
    elif(sport not in flow[srcAddress][protocol]):
        flow[srcAddress][protocol][sport] = {}
        flow[srcAddress][protocol][sport][dstAddress] = []
        flow[srcAddress][protocol][sport][dstAddress].append(dport)
    elif(dstAddress not in flow[srcAddress][protocol][sport]):
        flow[srcAddress][protocol][sport][dstAddress] = []
        flow[srcAddress][protocol][sport][dstAddress].append(dport)
    elif(dport not in flow[srcAddress][protocol][sport][dstAddress]):
        flow[srcAddress][protocol][sport][dstAddress].append(dport)
    """----------------------------------------------------"""
    if(dstAddress not in flow):
        flow[dstAddress] = {}
        flow[dstAddress][1] = {}
        flow[dstAddress][2] = {}
        flow[dstAddress][protocol][dport] = {}
        flow[dstAddress][protocol][dport][srcAddress] = []
        flow[dstAddress][protocol][dport][srcAddress].append(sport)
    elif(dport not in flow[dstAddress][protocol]):
        flow[dstAddress][protocol][dport] = {}
        flow[dstAddress][protocol][dport][srcAddress] = []
        flow[dstAddress][protocol][dport][srcAddress].append(sport)
    elif(srcAddress not in flow[dstAddress][protocol][dport]):
        flow[dstAddress][protocol][dport][srcAddress] = []
        flow[dstAddress][protocol][dport][srcAddress].append(sport)
    elif(sport not in flow[dstAddress][protocol][dport][srcAddress]):
        flow[dstAddress][protocol][dport][srcAddress].append(sport)
    """----------------------------------------------------"""

def classifyPacket(packet): #funkcia pre klasifikaciu paketu
    global wasConvinced
    global flow
    global convinced
    global suspects
    wasConvinced = False
    packetLength = packet.getLength() 
    srcAddress = packet.getSrc()
    dstAddress = packet.getDst()
    sport = packet.getSport()
    dport = packet.getDport()
    protocol = packet.getProtocol()
    if(protocol == 0): #odfiltruje sa paket, ktory nie je ani TCP ani UDP
        return
    if(protocol == 1):
        helpProtocol = 2
    else:
        helpProtocol = 1
    if(netaddr.IPAddress(srcAddress).is_multicast() or netaddr.IPAddress(dstAddress).is_multicast()):
        return
    if(srcAddress == 4294967295 or dstAddress == 4294967295):
        return
    if(srcAddress in convinced):
        if(sport in convinced[srcAddress][protocol] or sport in convinced[srcAddress][helpProtocol]):
            if(sport not in convinced[srcAddress][protocol]):
                convinced[srcAddress][protocol].append(sport)
            if(dstAddress not in convinced):
                convinced[dstAddress] = {}
                convinced[dstAddress][1] = []
                convinced[dstAddress][2] = []
                convinced[dstAddress][protocol].append(dport)
            else:
                if(dport not in convinced[dstAddress][protocol]):
                    convinced[dstAddress][protocol].append(dport)
            return
    if(dstAddress in convinced):
        if(dport in convinced[dstAddress][protocol] or dport in convinced[dstAddress][helpProtocol]):
            if(dport not in convinced[dstAddress][protocol]):
                convinced[dstAddress][protocol].append(dport)
            if(srcAddress not in convinced):
                convinced[srcAddress] = {}
                convinced[srcAddress][1] = []
                convinced[srcAddress][2] = []
                convinced[srcAddress][protocol].append(sport)
            else:
                if(sport not in convinced[srcAddress][protocol]):
                    convinced[srcAddress][protocol].append(sport)
            return
    if(packet.getProtocol() == 1): #TCP pakety
        if((packetLength > 200 and packetLength < 600)): #velkost medzi 200-600 tracker komunikacia
            testTrackerCommunication(packet) #funkcia na odtestovanie pritomnosti tracker komunikacie
        if(packetLength > 100 and packetLength < 200): #velkost medzi 100-200 bajtov peer komunikacia
            testPeerCommunication(packet) #funkcia na odtestovanie pritomnosti peer komunikacie
    if(packet.getProtocol() == 2): #UDP pakety
        if(packetLength > 100 and packetLength < 200): #100-200 Bajtov peer komunikacia
            testPeerCommunication(packet) #funkcia na odtestovanie peer protokolu
    if(not wasConvinced and enableSuspects):
        flowAnalyser(packet)


def finalAnalyzer():
    global flow
    global convinced
    global suspects
    for address in flow:
        for port in flow[address][2]:
            if(len(flow[address][2][port]) > 30):
                if(address in convinced):
                    if(port in convinced[address][2]):
                        continue
                if(address not in suspects):                
                    suspects[address] = {}
                    suspects[address][1] = []
                    suspects[address][2] = []
                    suspects[address][2].append(port)
                elif (port not in suspects[address][2]):
                    suspects[address][2].append(port)
                
                for dstAddress in flow[address][2][port]:
                    for dport in flow[address][2][port][dstAddress]:
                        if(dstAddress in convinced):
                            if(dport in convinced[dstAddress][2]):
                                continue
                        if dstAddress not in suspects:
                            suspects[dstAddress] = {}
                            suspects[dstAddress][1] = []
                            suspects[dstAddress][2] = []
                            suspects[dstAddress][2].append(dport)
                        elif (dport not in suspects[address][2]):
                            suspects[dstAddress][2].append(dport)
        if (len(flow[address][1]) > 30):
            for port in flow[address][1]:
                if(address in convinced):
                    if(port in convinced[address][1]):
                        continue
                if(address not in suspects):                
                    suspects[address] = {}
                    suspects[address][1] = []
                    suspects[address][2] = []
                    suspects[address][1].append(port)
                elif (port not in suspects[address][1]):
                    suspects[address][1].append(port)
                
                for dstAddress in flow[address][1][port]:
                    for dport in flow[address][1][port][dstAddress]:
                        if(dstAddress in convinced):
                            if(dport in convinced[dstAddress][1]):
                                continue
                        if dstAddress not in suspects:
                            suspects[dstAddress] = {}
                            suspects[dstAddress][1] = []
                            suspects[dstAddress][2] = []
                            suspects[dstAddress][1].append(dport)
                        elif (dport not in suspects[dstAddress][1]):
                            suspects[dstAddress][1].append(dport)

    if len(suspects) > 0:
        tmpSuspects={}
        for address in suspects:
            for protocol in suspects[address]:
                for port in suspects[address][protocol]:
                    if (address in convinced):
                        if(port in convinced[address][protocol]):
                            continue
                    if(address not in tmpSuspects):
                        tmpSuspects[address]={}
                        tmpSuspects[address][1] = []
                        tmpSuspects[address][2] = []
                        tmpSuspects[address][protocol].append(port)
                    elif(port not in tmpSuspects[address][protocol]):
                        tmpSuspects[address][protocol].append(port)
        suspects = tmpSuspects

def stringifyInfoHash(infoString):
    finalString=""
    for letter in infoString:
        ch = hex(ord(letter))[2:]
        if(len(ch) < 2):
            ch = str(0) + ch
        finalString += ch
    return finalString

def xmlOut(args):
    global enableSuspects
    global network
    global mask
    global debugConvinced
    global debugSuspected
    global debugConvincedTCPPorts
    global debugConvincedUDPPorts
    global debugSuspectedTCPPorts
    global debugSuspectedUDPPorts
    global debugInfoHashes

    root = ET.Element("Root")
    convincedLocal = collections.OrderedDict(sorted(convinced.items()))
    suspectsLocal = collections.OrderedDict(sorted(suspects.items()))
    if(len(convinced) > 0):
        subroot = ET.SubElement(root, "Convinced")
        for address in convincedLocal:
            if(network != None):
                if(isinstance(address,int)):
                    if(address & mask != network):
                        continue
                else:
                    continue
            debugConvinced += 1
            IP = ET.SubElement(subroot, "IP", name=str(netaddr.IPAddress(address)))
            if(len(convincedLocal[address][1]) > 0):
                protocol = ET.SubElement(IP, "TCP")
                for port in convincedLocal[address][1]:
                    ET.SubElement(protocol, "Port").text = str(port)
                    debugConvincedTCPPorts += 1
            if(len(convincedLocal[address][2]) > 0):
                protocol = ET.SubElement(IP, "UDP")
                for port in convincedLocal[address][2]:
                    ET.SubElement(protocol, "Port").text = str(port)
                    debugConvincedUDPPorts += 1
        
    if(enableSuspects):
        if(len(suspects)>0):
            subroot = ET.SubElement(root, "Suspected")
            for address in suspectsLocal:
                if(network != None):
                    if(isinstance(address,int)):
                        if(address & mask != network):
                            continue
                    else:
                        continue
                if(address not in convinced):
                    debugSuspected += 1
                IP = ET.SubElement(subroot, "IP", name=str(netaddr.IPAddress(address)))
                if(len(suspectsLocal[address][1]) > 0):
                    protocol = ET.SubElement(IP, "TCP")
                    for port in suspectsLocal[address][1]:
                        ET.SubElement(protocol, "Port").text = str(port)
                        debugSuspectedTCPPorts += 1
                if(len(suspectsLocal[address][2]) > 0):
                    protocol = ET.SubElement(IP, "UDP")
                    for port in suspectsLocal[address][2]:
                        ET.SubElement(protocol, "Port").text = str(port)
                        debugSuspectedUDPPorts += 1

    if(len(info_hashes)>0):
        subroot = ET.SubElement(root, "Info_Hashes")
        for ihash in info_hashes:
            ET.SubElement(subroot, "Hash").text = ihash
            debugInfoHashes += 1
    tree = ET.ElementTree(root)
    root = tree.getroot()
    xmlstr = minidom.parseString(ET.tostring(root)).toprettyxml(indent="    ")
    if(args.getOutputFile() != None):
        with open(args.getOutputFile(), "w") as f:
            f.write(xmlstr)
    else:
        print(xmlstr)

def debugOut():
    global debugConvinced
    global debugSuspected
    global debugConvincedTCPPorts
    global debugConvincedUDPPorts
    global debugSuspectedTCPPorts
    global debugSuspectedUDPPorts

    print("Number of IPs: " + str(debugConvinced + debugSuspected))
    print("    Number of convinced IPs: "+ str(debugConvinced))
    print("    Number of suspected IPs: "+ str(debugSuspected))
    print("Number of ports: " + str(debugConvincedTCPPorts + debugConvincedUDPPorts + debugSuspectedTCPPorts + debugSuspectedUDPPorts))
    print("    Number of TCP ports: " + str(debugConvincedTCPPorts + debugSuspectedTCPPorts))
    print("        Number of convinced TCP ports: " + str(debugConvincedTCPPorts))
    print("        Number of suspected TCP ports: " + str(debugSuspectedTCPPorts))

    print("    Number of UDP ports: " + str(debugConvincedUDPPorts + debugSuspectedUDPPorts))
    print("        Number of convinced UDP ports: " + str(debugConvincedUDPPorts))
    print("        Number of suspected UDP ports: " + str(debugSuspectedUDPPorts))

    print("Number of infohashes:" + str(debugInfoHashes))


def main():
    args = arguments() #instancializacia 
    global enableSuspects
    global network
    enableSuspects = args.getEnableSuspects() #priradenie do globalnej premennej
    network = args.getNetwork()
    if(args.getFile() == None): #osetrenie pripadu bez vstupneho suboru
        print("No pcap file inserted. Please, use \"-f filename\" as an argument")
        return
    f=file(args.getFile(),"rb") #otvorenie suboru
    pcap = dpkt.pcap.Reader(f) #instancializacia citaca pcapov
    packet = packetClass() #instancializacia premennej packetClass
    
    for ts, pkt in pcap: #cyklus citania pcapu
        packet.decodePacket(pkt) #dekodovanie paketu - vytiahnutie informacii potrebnych pre detekciu
        classifyPacket(packet) #funkcia pre klasifikaciu paketu
        packet.destroyPacket() #zrusi obsah paketu
    if(enableSuspects):
        finalAnalyzer() #v pripade povolenia suspectov urobi analyzu nad tokmi
    xmlOut(args)
    if(args.getDebug()):
        debugOut()
main()