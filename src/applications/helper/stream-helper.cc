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
#include "stream-helper.h"
#include "ns3/stream-server.h"
#include "ns3/stream-client.h"
#include "ns3/uinteger.h"
#include "ns3/names.h"


namespace ns3 {

StreamServerHelper::StreamServerHelper (uint16_t port)
{
  m_factory.SetTypeId (StreamServer::GetTypeId ());
  SetAttribute ("Port", UintegerValue (port));
}

void
StreamServerHelper::SetAttribute (
  std::string name,
  const AttributeValue &value)
{
  m_factory.Set (name, value);
}

ApplicationContainer
StreamServerHelper::Install (Ptr<Node> node) const
{
  return ApplicationContainer (InstallPriv (node));
}

ApplicationContainer
StreamServerHelper::Install (std::string nodeName) const
{
  Ptr<Node> node = Names::Find<Node> (nodeName);
  return ApplicationContainer (InstallPriv (node));
}

ApplicationContainer
StreamServerHelper::Install (NodeContainer c) const
{
  ApplicationContainer apps;
  for (NodeContainer::Iterator i = c.Begin (); i != c.End (); ++i)
    {
      apps.Add (InstallPriv (*i));
    }

  return apps;
}

Ptr<Application>
StreamServerHelper::InstallPriv (Ptr<Node> node) const
{
  Ptr<Application> app = m_factory.Create<StreamServer> ();
  node->AddApplication (app);

  return app;
}

// ywj
void 
StreamServerHelper::SetIniRTT0 (Time rtt0)
{
  owd_0_vs = rtt0;
}

void 
StreamServerHelper::SetIniRTT1 (Time rtt1)
{
  owd_1_vs = rtt1;
}

void 
StreamServerHelper::SetBW0 (DataRate bw0)
{
  bw_0_vs = bw0;
}

void 
StreamServerHelper::SetBW1 (DataRate bw1)
{
  bw_1_vs = bw1;
}

void 
StreamServerHelper::SetER (double error_p)
{
  errorRate_vs = error_p;
}

void 
StreamServerHelper::SetScheAlgo (double Algo)
{
  m_pktScheAlgo_vs = Algo; //1. quic-rr (quic with round-robin), 2, mpquic-rr, 3. mpquic-ofo (our proposed scheduler for solving ofo issue)
}

void 
StreamServerHelper::WithMobility (bool mob)
{
  withMob_vs = mob;
}


StreamClientHelper::StreamClientHelper (Address address, uint16_t port)
{
  m_factory.SetTypeId (StreamClient::GetTypeId ());
  SetAttribute ("RemoteAddress", AddressValue (address));
  SetAttribute ("RemotePort", UintegerValue (port));
}

StreamClientHelper::StreamClientHelper (Ipv4Address address, uint16_t port)
{
  m_factory.SetTypeId (StreamClient::GetTypeId ());
  SetAttribute ("RemoteAddress", AddressValue (Address(address)));
  SetAttribute ("RemotePort", UintegerValue (port));
}

StreamClientHelper::StreamClientHelper (Ipv6Address address, uint16_t port)
{
  m_factory.SetTypeId (StreamClient::GetTypeId ());
  SetAttribute ("RemoteAddress", AddressValue (Address(address)));
  SetAttribute ("RemotePort", UintegerValue (port));
}

void
StreamClientHelper::SetAttribute (std::string name, const AttributeValue &value)
{
  m_factory.Set (name, value);
}

ApplicationContainer
StreamClientHelper::Install (std::vector <std::pair <Ptr<Node>, std::string> > clients) const
{
  ApplicationContainer apps;
  for (uint i = 0; i < clients.size (); i++)
    {
      apps.Add (InstallPriv (clients.at (i).first, clients.at (i).second, i));
    }

  return apps;
}

Ptr<Application>
StreamClientHelper::InstallPriv (Ptr<Node> node, std::string algo, uint16_t clientId) const
{
  Ptr<Application> app = m_factory.Create<StreamClient> ();
  app->GetObject<StreamClient> ()->SetAttribute ("ClientId", UintegerValue (clientId));
  app->GetObject<StreamClient> ()->Initialise (algo, clientId);
  node->AddApplication (app);
  return app;
}

} // namespace ns3
