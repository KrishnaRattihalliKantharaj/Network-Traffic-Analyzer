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
    print("\nhere" + tgt)
    rec = gi.record_by_name(tgt)
    print(rec)
    if(rec is None):
        return
    else:
        city = rec['city']
        print(city)
        country = rec['country_name']
        long = rec['longitude']
        lat = rec['latitude']
        print (lat)
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

@csrf_exempt
def search(request):
    pcapFile = request.FILES['file_upload']
    fs = FileSystemStorage()
    filename = fs.save(pcapFile.name, pcapFile)
    uploaded_file_url = fs.url(filename)
    f = open(uploaded_file_url, 'rb')
    pcap = dpkt.pcap.Reader(f)
    unique = printPcap(pcap)
    print("\nreached6")
    js = []
    for item in unique:
        print("\nitem after 6 = " + str(item))
        obj = {"IP": str(item[0]), "Lat": str(item[1]), "Long": str(item[2]), "City": str(item[3]),
               "Country": str(item[4])}
        js.append(obj)
        lat = str(item[1])
        lng = str(item[2])
        ip = str(item[0])
        city = str(item[3])
        country = str(item[4])

    return HttpResponse(render_to_response('results.html', {'data': js}))
