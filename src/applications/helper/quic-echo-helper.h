/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
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
 *
 * Authors: Davide Marcato <davide.marcato.4@studenti.unipd.it>
 *          Stefano Ravazzolo <stefano.ravazzolo@studenti.unipd.it>
 *          Alvise De Biasio <alvise.debiasio@studenti.unipd.it>
 */

#ifndef QUIC_ECHO_HELPER_H
#define QUIC_ECHO_HELPER_H

#include <stdint.h>
#include "ns3/application-container.h"
#include "ns3/node-container.h"
#include "ns3/object-factory.h"
#include "ns3/ipv4-address.h"
#include "ns3/ipv6-address.h"

#include "ns3/network-module.h"

namespace ns3 {

/**
 * \ingroup quicecho
 * \brief Create a server application which waits for input QUIC packets
 *        and sends them back to the original sender.
 */
class QuicEchoServerHelper
{
public:
  /**
   * Create QuicEchoServerHelper which will make life easier for people trying
   * to set up simulations with echos.
   *
   * \param port The port the server will wait on for incoming packets
   */
  QuicEchoServerHelper (uint16_t port);

  /**
   * Record an attribute to be set in each Application after it is is created.
   *
   * \param name the name of the attribute to set
   * \param value the value of the attribute to set
   */
  void SetAttribute (std::string name, const AttributeValue &value);

  /**
   * Create a QuicEchoServerApplication on the specified Node.
   *
   * \param node The node on which to create the Application.  The node is
   *             specified by a Ptr<Node>.
   *
   * \returns An ApplicationContainer holding the Application created,
   */
  ApplicationContainer Install (Ptr<Node> node) const;

  /**
   * Create a QuicEchoServerApplication on specified node
   *
   * \param nodeName The node on which to create the application.  The node
   *                 is specified by a node name previously registered with
   *                 the Object Name Service.
   *
   * \returns An ApplicationContainer holding the Application created.
   */
  ApplicationContainer Install (std::string nodeName) const;

  /**
   * \param c The nodes on which to create the Applications.  The nodes
   *          are specified by a NodeContainer.
   *
   * Create one quic echo server application on each of the Nodes in the
   * NodeContainer.
   *
   * \returns The applications created, one Application per Node in the
   *          NodeContainer.
   */
  ApplicationContainer Install (NodeContainer c) const;

private:
  /**
   * Install an ns3::QuicEchoServer on the node configured with all the
   * attributes set with SetAttribute.
   *
   * \param node The node on which an QuicEchoServer will be installed.
   * \returns Ptr to the application installed.
   */
  Ptr<Application> InstallPriv (Ptr<Node> node) const;

  ObjectFactory m_factory; //!< Object factory.
};
Time owd_0;  //one-way delay of path0
Time owd_1;
DataRate bw_0;
DataRate bw_1;
double errorRate;
double error_p2;

uint8_t m_pktScheAlgo;
bool withMob;

/**
 * \ingroup quicecho
 * \brief Create an application which sends a QUIC packet and waits for an echo of this packet
 */
class QuicEchoClientHelper
{
public:
  /**
   * Create QuicEchoClientHelper which will make life easier for people trying
   * to set up simulations with echos. Use this variant with addresses that do
   * not include a port value (e.g., Ipv4Address and Ipv6Address).
   *
   * \param ip The IP address of the remote quic echo server
   * \param port The port number of the remote quic echo server
   */
  QuicEchoClientHelper (Address ip, uint16_t port);
  /**
   * Create QuicEchoClientHelper which will make life easier for people trying
   * to set up simulations with echos. Use this variant with addresses that do
   * include a port value (e.g., InetSocketAddress and Inet6SocketAddress).
   *
   * \param addr The address of the remote quic echo server
   */
  QuicEchoClientHelper (Address addr);

  /**
   * Record an attribute to be set in each Application after it is is created.
   *
   * \param name the name of the attribute to set
   * \param value the value of the attribute to set
   */
  void SetAttribute (std::string name, const AttributeValue &value);

  /**
   * Given a pointer to a QuicEchoClient application, set the data fill of the
   * packet (what is sent as data to the server) to the contents of the fill
   * string (including the trailing zero terminator).
   *
   * \warning The size of resulting echo packets will be automatically adjusted
   * to reflect the size of the fill string -- this means that the PacketSize
   * attribute may be changed as a result of this call.
   *
   * \param app Smart pointer to the application (real type must be QuicEchoClient).
   * \param fill The string to use as the actual echo data bytes.
   */
  void SetFill (Ptr<Application> app, std::string fill);

  /**
   * Given a pointer to a QuicEchoClient application, set the data fill of the
   * packet (what is sent as data to the server) to the contents of the fill
   * byte.
   *
   * The fill byte will be used to initialize the contents of the data packet.
   *
   * \warning The size of resulting echo packets will be automatically adjusted
   * to reflect the dataLength parameter -- this means that the PacketSize
   * attribute may be changed as a result of this call.
   *
   * \param app Smart pointer to the application (real type must be QuicEchoClient).
   * \param fill The byte to be repeated in constructing the packet data..
   * \param dataLength The desired length of the resulting echo packet data.
   */
  void SetFill (Ptr<Application> app, uint8_t fill, uint32_t dataLength);

  /**
   * Given a pointer to a QuicEchoClient application, set the data fill of the
   * packet (what is sent as data to the server) to the contents of the fill
   * buffer, repeated as many times as is required.
   *
   * Initializing the fill to the contents of a single buffer is accomplished
   * by providing a complete buffer with fillLength set to your desired
   * dataLength
   *
   * \warning The size of resulting echo packets will be automatically adjusted
   * to reflect the dataLength parameter -- this means that the PacketSize
   * attribute of the Application may be changed as a result of this call.
   *
   * \param app Smart pointer to the application (real type must be QuicEchoClient).
   * \param fill The fill pattern to use when constructing packets.
   * \param fillLength The number of bytes in the provided fill pattern.
   * \param dataLength The desired length of the final echo data.
   */
  void SetFill (Ptr<Application> app, uint8_t *fill, uint32_t fillLength, uint32_t dataLength);



  void SetIniRTT0 (Time rtt0);

  void SetIniRTT1 (Time rtt1);

  void SetBW0 (DataRate bw0);

  void SetBW1 (DataRate bw1);

  void SetER (double error_p);
  
  void SetScheAlgo (double Algo);

  void WithMobility (bool mob);

  /**
   * Create a quic echo client application on the specified node.  The Node
   * is provided as a Ptr<Node>.
   *
   * \param node The Ptr<Node> on which to create the QuicEchoClientApplication.
   *
   * \returns An ApplicationContainer that holds a Ptr<Application> to the
   *          application created
   */
  ApplicationContainer Install (Ptr<Node> node) const;

  /**
   * Create a quic echo client application on the specified node.  The Node
   * is provided as a string name of a Node that has been previously
   * associated using the Object Name Service.
   *
   * \param nodeName The name of the node on which to create the QuicEchoClientApplication
   *
   * \returns An ApplicationContainer that holds a Ptr<Application> to the
   *          application created
   */
  ApplicationContainer Install (std::string nodeName) const;

  /**
   * \param c the nodes
   *
   * Create one quic echo client application on each of the input nodes
   *
   * \returns the applications created, one application per input node.
   */
  ApplicationContainer Install (NodeContainer c) const;

private:
  /**
   * Install an ns3::QuicEchoClient on the node configured with all the
   * attributes set with SetAttribute.
   *
   * \param node The node on which an QuicEchoClient will be installed.
   * \returns Ptr to the application installed.
   */
  Ptr<Application> InstallPriv (Ptr<Node> node) const;
  ObjectFactory m_factory; //!< Object factory.
};

} // namespace ns3

#endif /* QUIC_ECHO_HELPER_H */
