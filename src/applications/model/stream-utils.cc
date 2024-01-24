#include "ns3/log.h"
#include "ns3/assert.h"
#include "stream-utils.h"

namespace ns3 {

std::string
GetSocketFactoryNameFromProtocol (std::string protocolName) {
  NS_ASSERT (protocolName.size() > 1);

  // Convert protocol name to title case
  for (std::size_t i = 0; i < protocolName.size(); ++i) 
    {
      char letter = protocolName.at(i);
      if (i == 0) 
        {
          protocolName.at(i) = std::toupper (letter);
        }
      else 
        {
          protocolName.at(i) = std::tolower (letter);
        }
    }
  
  return "ns3::" + protocolName + "SocketFactory"; // E.g. QuicSocketFcatory
}

bool
IsQuicString (std::string s) {
  std::string lower {""};
  for (auto c : s) {
    lower.push_back (std::tolower(c));
  }

  return lower == "quic";
}

} // namespace ns-3

