# -*- coding: utf-8 -*-
from django.shortcuts import render
from django.http import HttpResponse
from django.template import Template, Context
from django.template.loader import get_template
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
import dpkt
import socket
import pygeoip
from django.shortcuts import render
from django.conf import settings
from django.core.files.storage import FileSystemStorage
from django.shortcuts import render_to_response

gi = pygeoip.GeoIP('GeoLiteCity.dat')
def index(request):
    return render(request,'home.html')


def printRecord(tgt):
    rec = gi.record_by_name(tgt)
    if(rec is not None):
        city = rec['city']
        country = rec['country_name']
        long = rec['longitude']
        lat = rec['latitude']
        return (tgt, lat, long, city, country)


def checkBLSiteAccess(src, dst):
    blacklistedSites = {
        '10.250.197.182'
    }
    if(dst in blacklistedSites):
        #print("\n Black Listed IP destination accessed by = " + src)
        uniqueLatLong = printRecord(src)
        return uniqueLatLong
    else:
        return 0

def extractIPs(uploaded_file_url):

    return allSrcIPs


def placeMarkers(ip_addressess):
    markers = []
    for ip_address in ip_addressess:
        obj = {"IP": str(ip_address[0]), "Lat": str(ip_address[1]), "Long": str(ip_address[2]),
               "City": str(ip_address[3]),
               "Country": str(ip_address[4])}
        markers.append(obj)
        lat = str(ip_address[1])
        lng = str(ip_address[2])
        ip = str(ip_address[0])
        city = str(ip_address[3])
        country = str(ip_address[4])
    return markers

#*********************API's being called from Frontend***************************

@csrf_exempt
def findAllIPs(request):
    fs = FileSystemStorage()
    try:
        pcapFile = request.FILES['file_upload']
        filename = fs.save(pcapFile.name, pcapFile)
        uploaded_file_url = fs.url(filename)
    except:
        print("\nFAILED SO REACHED EXCEPT")
        filename = request.GET['filename']
        print("\n filename = " + filename)
        uploaded_file_url = fs.url(filename)
        print("\nuploaded_file_url = " + uploaded_file_url)
    f1 = open(uploaded_file_url, 'rb')
    pcap = dpkt.pcap.Reader(f1)
    src = ""
    srcDst = {}
    uniqueSrc = set()
    for (ts, buf) in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
            if src not in uniqueSrc:
                uniqueSrc.add(src)
                srcDst[src] = dst
        except:
            pass
    allSrcIPs = set()
    for src in uniqueSrc:
        if(printRecord(src) is not None):
            allSrcIPs.add(printRecord(src))
    markers = placeMarkers(allSrcIPs)

    return HttpResponse(render_to_response('results.html', {'data': markers, 'filename' : filename}))


def findBLAccessingIPs(request):
    filename = request.GET['filename']
    fs = FileSystemStorage()
    uploaded_file_url = fs.url(filename)
    f1 = open(uploaded_file_url, 'rb')
    pcap = dpkt.pcap.Reader(f1)
    src = ""
    srcDst = {}
    uniqueSrc = set()
    for (ts, buf) in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
            if src not in uniqueSrc:
                uniqueSrc.add(src)
                srcDst[src] = dst
        except:
            pass
    BLAccess = set()
    #print(srcDst)
    for src in uniqueSrc:
        found = checkBLSiteAccess(src, srcDst[src])
        if found and found is not None:
            BLAccess.add(found)
    markers = placeMarkers(BLAccess)
    return HttpResponse(render_to_response('results.html', {'data': markers, 'filename' : filename}))



def findDownloads(request):
    fs = FileSystemStorage()
    filename = request.GET['filename']
    uploaded_file_url = fs.url(filename)
    anythingDownloaded = "false"
    f = open(uploaded_file_url, 'rb')
    pcap = dpkt.pcap.Reader(f)
    for (ts, buf) in pcap:
        eth = dpkt.ethernet.Ethernet(buf)               # Unpack the Ethernet frame (mac src/dst, ethertype)

        if not isinstance(eth.data, dpkt.ip.IP):        # Make sure the Ethernet data contains an IP packet
            continue                                    #print ('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)

        ip = eth.data                                   # Now grab the data within the Ethernet frame (the IP packet)
        src = socket.inet_ntoa(ip.src)
        if isinstance(ip.data, dpkt.tcp.TCP):           # Check for TCP in the transport layer
            tcp = ip.data                               # Set the TCP data
            try:                                        # Now see if we can parse the contents as a HTTP request
                http = dpkt.http.Request(tcp.data)
                if http.method == 'GET':
                    uri = http.uri.lower()
                    if '.zip' in uri or '.ZIP' in uri:
                        anythingDownloaded = "true"
                        print("\nZIP file downloaded by " + src + " from " + uri)
            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                continue
    if (anythingDownloaded is "false"):
        print("\nNo ZIP File Downloaded\n")
    return HttpResponse(render_to_response('results.html', {'filename': filename}))



