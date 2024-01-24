/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright 2020 University of Victoria
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

#ifndef STREAM_UTILS_H
#define STREAM_UTILS_H

#include <string>
#include <cctype>

namespace ns3 {

/**
 * @brief Get the string name of the SocketFactory for the given protocol
 * 
 * @param protocolName The name of a transport protocol like "TCP"
 * @return std::string The queryable ns-3 name of a socket factory
 */
std::string GetSocketFactoryNameFromProtocol (std::string protocolName);

/**
 * @brief Answers whether the given string represents the QUIC protocol
 */
bool IsQuicString (std::string);

} // namespace ns3

#endif /* STREAM_UTILS_H */
