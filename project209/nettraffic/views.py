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
    if(rec is None):
        return
    else:
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
        print("\n Black Listed IP destination accessed by = " + src)
        uniqueLatLong = printRecord(src)
        return uniqueLatLong
    else:
        return 0

def printPcap(uploaded_file_url):
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
    return BLAccess

def findDownload(uploaded_file_url):
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


@csrf_exempt
def search(request):
    pcapFile = request.FILES['file_upload']
    fs = FileSystemStorage()
    filename = fs.save(pcapFile.name, pcapFile)
    uploaded_file_url = fs.url(filename)
    unique = printPcap(uploaded_file_url)
    findDownload(uploaded_file_url)
    js = []
    for item in unique:
        obj = {"IP": str(item[0]), "Lat": str(item[1]), "Long": str(item[2]), "City": str(item[3]),
               "Country": str(item[4])}
        js.append(obj)
        lat = str(item[1])
        lng = str(item[2])
        ip = str(item[0])
        city = str(item[3])
        country = str(item[4])
    return HttpResponse(render_to_response('results.html', {'data': js}))



