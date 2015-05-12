#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#Author: St0rn
#Using: Scapy
#Description: Port Knocking server (4 ports) with anti-bruteforce
#

####### Import #################################################################

from threading import *
import socket
import os
import sys
import time


try:
 from scapy.all import *
except:
 print "\n scapy is not installed in your system\nInstalling...\n"
 os.system("apt-get install scapy")


############ Variables #########################################################

"""Pour lister tout les objets"""
knocker_list=list()
"""Pour stocker l'emplacement d'un objet"""
KnockerNb=int()
"""Liste pour s'assurer de la présence d'un host dans la liste d'objets"""
IsKnocker=list()
"""Variable pour declarer un objet"""
Knocker=str()
"""Liste pour iptables"""
iptables=list()



############ Classe ############################################################

"""Classe pour les knockers"""
class knockerObj:

 """Initialisation"""
 def __init__(self,ip_addr):
  self.ip=ip_addr
  self.port1=0
  self.port2=0
  self.port3=0

 """Remise à zero des variables port"""
 def XorPort(self):
  self.port1=0
  self.port2=0
  self.port3=0


 """Autorise l'host à accéder au port"""
 def Autorized(self):
  os.system("iptables -F")
  for host in iptables:
   os.system("iptables -A INPUT -p tcp -s " + host + " --dport 8080 -j ACCEPT")
  os.system("iptables -A INPUT -p tcp --dport 8080 -j REJECT --reject-with tcp-reset")


############ Functions #########################################################

"""Effacer le CLI"""
def Clear():
 os.system("clear")


"""Fonction pour recuperer l'emplacement d'un knocker selon sont ip"""
def ReturnKnocker(ip):
 for nb in xrange(len(knocker_list)):
  if knocker_list[nb].ip==ip:
   return nb

"""Etablissement de la regle iptable, on ne filtre pas le port on le rejete via un reset, simulation de port fermé"""
def init_rule():
 os.system("iptables -A INPUT -p tcp --dport 8080 -j REJECT --reject-with tcp-reset")

"""Fonction pour le port knocking"""
def PortKnocking(p):
 if p.haslayer(IP) and p.haslayer(TCP):
  ip=p.getlayer(IP)
  tcp=p.getlayer(TCP)


  """Gestion Knocking et anti bruteforce"""
  """Une requette sur le port 86 definit un knocker"""
  if tcp.dport==86:
   Knocker=knockerObj(ip.src)
   knocker_list.append(Knocker)
   if ip.src not in IsKnocker:
    IsKnocker.append(ip.src)

  """Premier port"""
  if tcp.dport==1337 and ip.src in IsKnocker:
   knocker=ReturnKnocker(ip.src)
   if knocker_list[KnockerNb].port1==0 and knocker_list[KnockerNb].port2==0 and knocker_list[KnockerNb].port3==0:
    knocker_list[KnockerNb].port1=1
   else:
    knocker_list[KnockerNb].XorPort()

  """Deuxieme port"""
  if tcp.dport==69 and ip.src in IsKnocker:
   knocker=ReturnKnocker(ip.src)
   if knocker_list[KnockerNb].port1==1 and knocker_list[KnockerNb].port2==0 and knocker_list[KnockerNb].port3==0:
    knocker_list[KnockerNb].port2=1
   else:
    knocker_list[KnockerNb].XorPort()

  """Troisieme port"""
  if tcp.dport==1664 and ip.src in IsKnocker:
   knocker=ReturnKnocker(ip.src)
   if knocker_list[KnockerNb].port1==1 and knocker_list[KnockerNb].port2==1 and knocker_list[KnockerNb].port3==0:
    knocker_list[KnockerNb].port3=1
    if knocker_list[KnockerNb].port1==1 and knocker_list[KnockerNb].port2==1 and knocker_list[KnockerNb].port3==1:
      IsKnocker.remove(knocker_list[knocker].ip)
      if knocker_list[knocker].ip not in iptables:
       iptables.append(knocker_list[knocker].ip)
      knocker_list[KnockerNb].Autorized()
      print "%s is granted!" %(knocker_list[KnockerNb].ip)
      knocker_list[KnockerNb].XorPort()
    else:
     knocker_list[KnockerNb].XorPort()

########################## Main ################################################

if __name__=="__main__":
 Clear()
 try:
  init_rule()
  print "[*] Rule added!"
 except:
  print "Can't add iptables rules... iptables is installed?"

 try:
  sniff(prn=PortKnocking)
 except KeyboardInterrupt, e:
  print "\nQuitting.. Remove all iptables rules.."
  os.system("iptables -F")
  sys.exit(0)
