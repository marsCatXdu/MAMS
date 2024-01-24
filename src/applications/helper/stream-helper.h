/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2008 INRIA
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
 *
 * Author: Mathieu Lacage <mathieu.lacage@sophia.inria.fr>
 */
#ifndef STREAM_HELPER_H
#define STREAM_HELPER_H

#include <stdint.h>
#include "ns3/application-container.h"
#include "ns3/node-container.h"
#include "ns3/object-factory.h"
#include "ns3/ipv4-address.h"
#include "ns3/ipv6-address.h"
#include "ns3/data-rate.h"

namespace ns3 {

    //ywj
  Time owd_0_vs;  //one-way delay of path0
  Time owd_1_vs;
  DataRate bw_0_vs;
  DataRate bw_1_vs;
  double errorRate_vs;
  double error_p2_vs;
  uint8_t m_pktScheAlgo_vs;
  bool withMob_vs;

/**
 * \ingroup dashStream
 * \brief Create a server application which waits for input UDP packets
 *        and sends them back to the original sender.
 */
class StreamServerHelper
{
public:
  /**
   * Create StreamServerHelper which will make life easier for people trying
   * to set up simulations with echos.
   *
   * \param port The port the server will wait on for incoming packets
   */
  StreamServerHelper (uint16_t port);



  void SetFill (Ptr<Application> app, uint8_t *fill, uint32_t fillLength, uint32_t dataLength);


  void SetIniRTT0 (Time rtt0);

  void SetIniRTT1 (Time rtt1);

  void SetBW0 (DataRate bw0);

  void SetBW1 (DataRate bw1);

  void SetER (double error_p);
  
  void SetScheAlgo (double Algo);

  void WithMobility (bool mob);

  /**
   * Record an attribute to be set in each Application after it is is created.
   *
   * \param name the name of the attribute to set
   * \param value the value of the attribute to set
   */
  void SetAttribute (std::string name, const AttributeValue &value);

  /**
   * Create a StreamServerApplication on the specified Node.
   *
   * \param node The node on which to create the Application.  The node is
   *             specified by a Ptr<Node>.
   *
   * \returns An ApplicationContainer holding the Application created,
   */
  ApplicationContainer Install (Ptr<Node> node) const;

  /**
   * Create a StreamServerApplication on specified node
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
   * Create one stream server application on each of the Nodes in the
   * NodeContainer.
   *
   * \returns The applications created, one Application per Node in the 
   *          NodeContainer.
   */
  ApplicationContainer Install (NodeContainer c) const;

private:
  /**
   * Install an ns3::StreamServer on the node configured with all the
   * attributes set with SetAttribute.
   *
   * \param node The node on which an StreamServer will be installed.
   * \returns Ptr to the application installed.
   */
  Ptr<Application> InstallPriv (Ptr<Node> node) const;

  ObjectFactory m_factory; //!< Object factory.
};

/**
 * \ingroup dashStream
 * \brief Create an application which sends a UDP packet and waits for an echo of this packet
 */
class StreamClientHelper
{
public:
  /**
   * Create StreamClientHelper which will make life easier for people trying
   * to set up simulations with echos.
   *
   * \param ip The IP address of the remote stream server
   * \param port The port number of the remote stream server
   */
  StreamClientHelper (Address ip, uint16_t port);
  /**
   * Create StreamClientHelper which will make life easier for people trying
   * to set up simulations with echos.
   *
   * \param ip The IPv4 address of the remote stream server
   * \param port The port number of the remote stream server
   */
  StreamClientHelper (Ipv4Address ip, uint16_t port);
  /**
   * Create StreamClientHelper which will make life easier for people trying
   * to set up simulations with echos.
   *
   * \param ip The IPv6 address of the remote stream server
   * \param port The port number of the remote stream server
   */
  StreamClientHelper (Ipv6Address ip, uint16_t port);

  /**
   * Record an attribute to be set in each Application after it is is created.
   *
   * \param name the name of the attribute to set
   * \param value the value of the attribute to set
   */
  void SetAttribute (std::string name, const AttributeValue &value);

  /**
   * \param clients the nodes with the name of the adaptation algorithm to be used
   *
   * Create one  stream client application on each of the input nodes and
   * instantiate an adaptation algorithm on each of the stream client according
   * to the given string.
   *
   * \returns the applications created, one application per input node.
   */
  ApplicationContainer Install (std::vector <std::pair <Ptr<Node>, std::string> > clients) const;

private:
  /**
   * Install an ns3::StreamClient on the node configured with all the
   * attributes set with SetAttribute.
   *
   * \param node The node on which an StreamClient will be installed.
   * \param algo A string containing the name of the adaptation algorithm to be used on this client
   * \param clientId distinguish this client object from other parallel running clients, for logging purposes
   * \param simulationId distinguish this simulation from other subsequently started simulations, for logging purposes
   * \returns Ptr to the application installed.
   */
  Ptr<Application> InstallPriv (Ptr<Node> node, std::string algo, uint16_t clientId) const;
  ObjectFactory m_factory; //!< Object factory.
};

} // namespace ns3

#endif /* STREAM_HELPER_H */
