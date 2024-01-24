/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright 2016 Technische Universitaet Berlin
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "ns3/log.h"
#include "ns3/ipv4-address.h"
#include "ns3/ipv6-address.h"
#include "ns3/address-utils.h"
#include "ns3/nstime.h"
#include "ns3/inet-socket-address.h"
#include "ns3/inet6-socket-address.h"
#include "ns3/socket.h"
#include "ns3/simulator.h"
#include "ns3/socket-factory.h"
#include "ns3/packet.h"
#include "ns3/uinteger.h"
#include "stream-server.h"
#include "ns3/global-value.h"
#include <ns3/core-module.h>
#include "ns3/trace-source-accessor.h"
#include "stream-utils.h"
#include "ns3/trace-source-accessor.h"


namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("StreamServerApplication");

NS_OBJECT_ENSURE_REGISTERED (StreamServer);

TypeId
StreamServer::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::StreamServer")
    .SetParent<Application> ()
    .SetGroupName ("Applications")
    .AddConstructor<StreamServer> ()
    .AddAttribute ("Port", "Port on which we listen for incoming packets.",
                   UintegerValue (9),
                   MakeUintegerAccessor (&StreamServer::m_port),
                   MakeUintegerChecker<uint16_t> ())
    .AddAttribute ("TransportProtocol", 
                   "The transport protocol used to communicate with clients",
                   StringValue ("QUIC"),
                   MakeStringAccessor (&StreamServer::m_protocolName),
                   MakeStringChecker ())
  ;
  return tid;
}

StreamServer::StreamServer ()
{
  NS_LOG_FUNCTION (this);
}

StreamServer::~StreamServer ()
{
  NS_LOG_FUNCTION (this);
  m_socket = 0;
  m_socket6 = 0;
}

void
StreamServer::DoDispose (void)
{
  NS_LOG_FUNCTION (this);
  Application::DoDispose ();
}

void
StreamServer::StartApplication (void)
{
  NS_LOG_FUNCTION (this);

  // Create a TCP or QUIC socket depending on how the client is configured.
  NS_LOG_INFO ("Creating " << m_protocolName << " socket");  
  std::string socketFactoryName = GetSocketFactoryNameFromProtocol (m_protocolName);
  auto socketTid = TypeId::LookupByName (socketFactoryName);

  if (m_socket == 0)
    {
      m_socket = Socket::CreateSocket (GetNode (), socketTid);
      InetSocketAddress local = InetSocketAddress (Ipv4Address::GetAny (), m_port);
      m_socket->Bind (local);
      m_socket->Listen ();
    }

/*   if (m_socket6 == 0)
    {
      m_socket6 = Socket::CreateSocket (GetNode (), socketTid);
      Inet6SocketAddress local6 = Inet6SocketAddress (Ipv6Address::GetAny (), m_port);
      m_socket6->Bind (local6);
      m_socket->Listen ();
    } */

  // Accept connection requests from remote hosts.
  m_socket->SetAcceptCallback (MakeCallback (&StreamServer::HandleConnectionRequest, this),
                               MakeCallback (&StreamServer::HandleAccept, this));
  m_socket->SetCloseCallbacks (
    MakeCallback (&StreamServer::HandlePeerClose, this),
    MakeCallback (&StreamServer::HandlePeerError, this));
}

void
StreamServer::StopApplication ()
{
  NS_LOG_FUNCTION (this);

  if (m_socket != 0)
    {
      m_socket->Close ();
      m_socket->SetRecvCallback (MakeNullCallback<void, Ptr<Socket> > ());
    }
  if (m_socket6 != 0)
    {
      m_socket6->Close ();
      m_socket6->SetRecvCallback (MakeNullCallback<void, Ptr<Socket> > ());
    }
}

void
StreamServer::HandleRead (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
  Ptr<Packet> packet;
  // ywj: In order to support dash over multipath QUIC, we have to obtain remote address through our newly defined function GetRemoteAddr,
  // because currently, the code structure of MPQUIC is one quic-socket bond with two udp sockets. The variable socket here stands for quic socket 
  // instead of udp socket, so after two udp sockets are associated with this quic socket, quic socket has no clue which udp socket the data comes from
  Address from = socket->GetRemoteAddr();
  packet = socket->RecvFrom (from);
  // RecvFrom would messy the value of from again, so we should use GetRemoteAddr to get it back correct
  from = socket->GetRemoteAddr();
  int64_t packetSizeToReturn = GetCommand (packet);

  NS_LOG_INFO("Server received request for segment " << m_callbackData [from].currentSegmentIndex << " of size " << packetSizeToReturn 
              << " from address: "<< InetSocketAddress::ConvertFrom (from).GetIpv4());
  std::cout<<"StreamServer::HandleRead "<<"Server received request for segment " << m_callbackData [from].currentSegmentIndex << " of size " << packetSizeToReturn 
  << " from address: "<< InetSocketAddress::ConvertFrom (from).GetIpv4()<<std::endl;

  if (m_callbackData [from].send || m_callbackData [from].currentTxBytes > 0) {
    NS_ABORT_MSG("Server received request from " << from << " before previous one was completed");
  }

  // these values will be accessible by the clients Address from.
  m_callbackData [from].currentTxBytes = 0;
  m_callbackData [from].packetSizeToReturn = packetSizeToReturn;
  m_callbackData [from].send = true;

  // Manually invoke the send callback. The callback will repeatedly be 
  // called by the socket as Tx space opens up following this call. 
  HandleSend (socket, socket->GetTxAvailable ());
}


void
StreamServer::HandleSend (Ptr<Socket> socket, uint32_t txSpace)
{
  NS_LOG_FUNCTION (this << socket << txSpace);

  // TODO try checking against the stream buffer available space too
  // Address from;
  // socket->GetPeerName (from);

  //ywj: obtain remote address
  Address from = socket->GetRemoteAddr();


    // std::cout<<"StreamServer::HandleSend "<<" from address: "<< InetSocketAddress::ConvertFrom (from).GetIpv4()<<std::endl;
  // look up values for the connected client and whose values are stored in from
  if (m_callbackData [from].currentTxBytes > m_callbackData [from].packetSizeToReturn) {
    NS_ABORT_MSG("Server has sent more data than required for the current segment.");
  } 
  else if (! m_callbackData [from].send) 
    {
      NS_ASSERT( m_callbackData [from].currentTxBytes == 0 );
      NS_LOG_LOGIC("Nothing to send. Current segment (" << (int)(m_callbackData [from].currentSegmentIndex) - 1 << ") marked as complete.");
    }
  else if (m_callbackData [from].currentTxBytes == m_callbackData [from].packetSizeToReturn)
    {
      NS_LOG_INFO("Marking current segment (" << (int)(m_callbackData [from].currentSegmentIndex) << ") as completed in server.");

      m_callbackData [from].currentTxBytes = 0;
      m_callbackData [from].packetSizeToReturn = 0;
      m_callbackData [from].send = false;
      m_callbackData [from].currentSegmentIndex++;

      return;
    }
  else if (txSpace > 0)
    {
      // Determine the amount of data we should send.
      // TODO it looks like QUIC's available() query only looks at the socket buffer, 
      //      but if the stream buffer cannot accomodate the new bytes, we won't be able to send
      //      the number of bytes which it claims to be available.
      long toSend;
      uint32_t remainingSegmentBytes = m_callbackData [from].packetSizeToReturn - m_callbackData [from].currentTxBytes;
      toSend = std::min (txSpace, remainingSegmentBytes);

      // Fill the packet with the current segment number so we can easily see
      // what is happening in Wireshark.
      uint8_t* packetData = new uint8_t [toSend];
      uint8_t currentSegmentBytesFiller = (uint8_t)(m_callbackData [from].currentSegmentIndex);
      std::fill(packetData, packetData + toSend, currentSegmentBytesFiller);
      Ptr<Packet> packet = Create<Packet> (packetData, toSend);

      NS_ASSERT (packet->GetSize() == toSend);
      NS_LOG_LOGIC("Server attempting to send " << toSend << " bytes. Tx space is " << txSpace);

      int amountSent {0};
      if (IsQuicString(m_protocolName)) {
        amountSent = socket->Send (packet, 1); // Send only on stream 1
      }
      else {
        amountSent = socket->Send (packet); // Don't use flags for TCP
      }

      if (amountSent > 0)
        {
          NS_LOG_INFO("Server sent " << amountSent << " bytes");
          m_callbackData [from].currentTxBytes += amountSent;
        }
      else
        {
          // We exit this part, when no bytes have been sent, as the send side buffer is full.
          // The "HandleSend" callback will fire when some buffer space has freed up.
          NS_LOG_WARN("Server send operation failed due to full send-side buffer.");
          return;
        }
    }
  else 
    {
      NS_LOG_WARN("Tx Socket Buffer Full. Send failed.");
    }
}

void
StreamServer::HandleAccept (Ptr<Socket> s, const Address& from)
{
  NS_LOG_FUNCTION (this << s << from);
  callbackData cbd;
  cbd.currentTxBytes = 0;
  cbd.packetSizeToReturn = 0;
  cbd.send = false;
  cbd.currentSegmentIndex = 0;
  m_callbackData [from] = cbd;
  m_connectedClients.push_back (from);
  s->SetRecvCallback ( MakeCallback (&StreamServer::HandleRead, this));
  s->SetSendCallback ( MakeCallback (&StreamServer::HandleSend, this));
}

void
StreamServer::HandlePeerClose (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
  Address from;
  socket->GetPeerName (from);
  for (std::vector<Address>::iterator it = m_connectedClients.begin (); it != m_connectedClients.end (); ++it)
    {
      if (*it == from)
        {
          m_connectedClients.erase (it);
          // No more clients left in m_connectedClients, simulation is done.
          if (m_connectedClients.size () == 0)
            {
              NS_LOG_INFO("No remaining client connections. Stopping simulator.");
              Simulator::Stop ();
            }
          return;
        }
    }
}

void
StreamServer::HandlePeerError (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
}

bool 
StreamServer::HandleConnectionRequest (Ptr<Socket> socket, const Address& from)
{
  NS_LOG_FUNCTION (this << socket << from);
  return true; // Accept all requests
}

int64_t
StreamServer::GetCommand (Ptr<Packet> packet)
{
  NS_LOG_FUNCTION(this << packet);
  int64_t packetSizeToReturn;
  uint8_t *buffer = new uint8_t [packet->GetSize ()];
  packet->CopyData (buffer, packet->GetSize ());
  std::stringstream ss;
  ss << buffer;
  std::string str;
  ss >> str;
  std::stringstream convert (str);
  convert >> packetSizeToReturn;
  return packetSizeToReturn;
}
} // Namespace ns3
