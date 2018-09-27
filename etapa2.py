#!/usr/bin/python3
# -*- encoding: utf-8 -*-
import socket
import select

IP = ""
PORT = 8080

class TCP:
	def __init__ (sourcePort, destinationPort, recvBuffer, lastAckSent):
		self.sourcePort = sourcePort
		self.destinationPort = destinationPort
		self.recvBuffer = recvBuffer
		self.lastAckSent = lastAckSent
