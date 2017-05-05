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


def printPcap(pcap):
    uniqueIP = set()
    for (ts, buf) in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
            uniqueIP.add(src)
        except:
            pass
    uniqueLatLong = set()
    for item in uniqueIP:

        try:
            Ull = printRecord(item)
            if (Ull is not None):
                uniqueLatLong.add(Ull)
            #uniqueLatLong.add(printRecord('130.65.10.101'))
            #uniqueLatLong.add(printRecord('130.65.136.10'))
        except:
            pass
    return uniqueLatLong

def findDownload(pcap):
    for (ts, buf) in pcap:
        # Unpack the Ethernet frame (mac src/dst, ethertype)
        eth = dpkt.ethernet.Ethernet(buf)

        # Make sure the Ethernet data contains an IP packet
        if not isinstance(eth.data, dpkt.ip.IP):
            print ('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
            continue

        # Now grab the data within the Ethernet frame (the IP packet)
        ip = eth.data
        src = socket.inet_ntoa(ip.src)

        # Check for TCP in the transport layer
        if isinstance(ip.data, dpkt.tcp.TCP):

            # Set the TCP data
            tcp = ip.data

            # Now see if we can parse the contents as a HTTP request
            try:
                http = dpkt.http.Request(tcp.data)
                if http.method == 'GET':
                    uri = http.uri.lower()
                    if '.zip' in uri and 'loic' in uri:
                        print("\nURL = " + uri)
                        print ('[!] ' + src + ' Downloaded LOIC.')
                    else:
                        print("\nNo Zip File Downloaded\n")
            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                continue
        else:
             print("\nNo TCP in transport layer in the given Pcap file.\n")


@csrf_exempt
def search(request):
    pcapFile = request.FILES['file_upload']
    fs = FileSystemStorage()
    filename = fs.save(pcapFile.name, pcapFile)
    uploaded_file_url = fs.url(filename)
    f = open(uploaded_file_url, 'rb')
    pcap = dpkt.pcap.Reader(f)

    filename1 = fs.save(pcapFile.name, pcapFile)
    uploaded_file_url1 = fs.url(filename1)
    f1 = open(uploaded_file_url1, 'rb')
    pcap1 = dpkt.pcap.Reader(f1)

    unique = printPcap(pcap1)
    findDownload(pcap)
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
