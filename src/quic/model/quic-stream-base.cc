/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2019 SIGNET Lab, Department of Information Engineering, University of Padova
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
 * Authors: Alvise De Biasio <alvise.debiasio@gmail.com>
 *          Federico Chiariotti <chiariotti.federico@gmail.com>
 *          Michele Polese <michele.polese@gmail.com>
 *          Davide Marcato <davidemarcato@outlook.com>
 *
 */
/*
#define NS_LOG_APPEND_CONTEXT \
  if (m_node and m_connectionId and (m_streamId >= 0)) { std::clog << " [node " << m_node->GetId () << " socket " << m_connectionId << " stream " << m_streamId << " " << StreamDirectionTypeToString () << "] "; }
*/

#include "ns3/abort.h"
#include "ns3/node.h"
#include "ns3/log.h"
#include "ns3/simulation-singleton.h"
#include "ns3/simulator.h"
#include "ns3/packet.h"
#include "ns3/uinteger.h"
#include "ns3/double.h"
#include "ns3/pointer.h"
#include "ns3/trace-source-accessor.h"
#include "quic-stream-base.h"
#include "quic-header.h"
#include "quic-transport-parameters.h"
#include <iomanip>
#include <cstring>
#include <stdlib.h>
#include <unistd.h>
#include <regex>

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("QuicStreamBase");

NS_OBJECT_ENSURE_REGISTERED (QuicStreamBase);

TypeId
QuicStreamBase::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::QuicStreamBase")
    .SetParent<QuicStream> ()
    .SetGroupName ("Internet")
    .AddConstructor<QuicStreamBase> ()
    .AddAttribute ("StreamSndBufSize",
                   "QuicStreamBase maximum transmit buffer size (bytes)",
                   UintegerValue (131072), // 128k
                   MakeUintegerAccessor (&QuicStreamBase::m_streamTxBufferSize),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("StreamRcvBufSize",
                   "QuicStreamBase maximum receive buffer size (bytes)",
                   UintegerValue (131072), // 128k
                   MakeUintegerAccessor (&QuicStreamBase::m_streamRxBufferSize),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("MaxDataInterval",
                   "Interval between MAX_DATA frames",
                   UintegerValue (15000),                 // 10 packets
                   MakeUintegerAccessor (&QuicStreamBase::m_maxDataInterval),
                   MakeUintegerChecker<uint32_t> ())
  ;
  return tid;
}

TypeId
QuicStreamBase::GetInstanceTypeId () const
{
  return QuicStreamBase::GetTypeId ();
}


QuicStreamBase::QuicStreamBase (void) 
  : QuicStream (),
  m_streamType (NONE),
  m_streamDirectionType (UNKNOWN),
  m_streamStateSend (IDLE),
  m_streamStateRecv (IDLE),
  m_node (0),
  m_connectionId (0),
  m_streamId (0),
  m_quicl5 (0),
  m_maxStreamData (0),
  m_maxAdvertisedData (0),
  m_sentSize (0),
  m_recvSize (0),
  m_fin (false)
{
  NS_LOG_FUNCTION (this);
  m_rxBuffer = CreateObject<QuicStreamRxBuffer> ();
  m_txBuffer = CreateObject<QuicStreamTxBuffer> ();
}

QuicStreamBase::~QuicStreamBase (void)
{
  NS_LOG_FUNCTION (this);
}

void
QuicStreamBase::SetQuicL5 (Ptr<QuicL5Protocol> quicl5)
{
  NS_LOG_FUNCTION (this);
  m_quicl5 = quicl5;
  SetStreamRcvBufSize (m_streamRxBufferSize);
  SetStreamSndBufSize (m_streamTxBufferSize);
}


int
QuicStreamBase::Send (Ptr<Packet> frame)
{
  NS_LOG_FUNCTION (this);

  SetStreamStateSendIf (m_streamStateSend == IDLE and (m_streamDirectionType == SENDER or m_streamDirectionType == BIDIRECTIONAL), OPEN);

  if (m_streamStateSend == OPEN or m_streamStateSend == SEND)
    {
      int sent = AppendingTx (frame);


      NS_LOG_LOGIC ("Sending packets in stream. TxBufSize = " << m_txBuffer->AppSize () << " AvailableWindow = " << AvailableWindow () << " state " << QuicStreamStateName[m_streamStateSend]);

      if ((m_streamStateSend == OPEN or m_streamStateSend == SEND) and AvailableWindow () > 0)
        {
          if (!m_streamSendPendingDataEvent.IsRunning ())
            {
              // std::cout<<"quic-stream-base.cc ----tst"<<std::endl;
              //m_streamSendPendingDataEvent = Simulator::Schedule (TimeStep (1), &QuicStreamBase::SendPendingData, this);
              if (m_quicl5->vnReceived)
              {
                // std::cout<<"****m_quicl5->vnReceived = 1";
                SendPendingData();
                m_quicl5->vnReceived = 0;

              }else{
                m_streamSendPendingDataEvent = Simulator::ScheduleNow (&QuicStreamBase::SendPendingData, this);
                // std::cout<<"quic-stream-base.cc ----sendpendingdata"<<std::endl;
              }
            }
        }
      return sent;
    }
  else
    {
      NS_ABORT_MSG ("Sending in state" << QuicStreamStateName[m_streamStateSend]);
      //m_errno = ERROR_NOTCONN;
      return -1;
    }
}

int
QuicStreamBase::AppendingTx (Ptr<Packet> frame)
{
  NS_LOG_FUNCTION (this);

  if (!m_txBuffer->Add (frame))
    {
      NS_LOG_WARN ("Exceeding Stream Tx Buffer Size");
      //m_quicl5->SignalAbortConnection (QuicSubheader::TransportErrorCodes_t::PROTOCOL_VIOLATION,
      //                                     "Received RST_STREAM in Stream 0");
      //m_errno = ERROR_MSGSIZE;
      return -1;
    }
  return frame->GetSize ();
}

uint32_t
QuicStreamBase::GetStreamTxAvailable () const
{
  return m_txBuffer->Available ();
}


uint32_t
QuicStreamBase::SendPendingData (void)
{
  NS_LOG_FUNCTION (this);

  if (m_txBuffer->AppSize () == 0)
    {
      NS_LOG_INFO ("Nothing to send");
      return false;
    }

  uint32_t nFrameSent = 0;
  uint32_t availableWindow = AvailableWindow ();

  while (availableWindow > 0 and m_txBuffer->AppSize () > 0)
    {
//	  uint32_t availableData = m_txBuffer->Available();

//	  if(availableData < availableWindow)
//	  {
//	          NS_LOG_INFO("Ask the app for more data before trying to send");
//		  NotifySend(GetTxAvailable());
//	  }

//	  if(availableWindow < m_quicl5->GetMaxPacketSize() and availableData > availableWindow)
//	  {
//	          NS_LOG_INFO("Preventing Silly Windows Syndrome. Wait to Send.");
//		  break;
//	  }


      uint32_t s = std::min (availableWindow, (uint32_t)m_quicl5->GetMaxPacketSize ());

      NS_LOG_DEBUG ("BEFOREAvailable Window " << AvailableWindow () <<
                    "Stream RWnd " << StreamWindow () <<
                    "BytesInFlight " << m_txBuffer->BytesInFlight () << "BufferedSize " << m_txBuffer->AppSize () <<
                    "MaxPacketSize " << (uint32_t)m_quicl5->GetMaxPacketSize ());

      int success = SendDataFrame ((SequenceNumber32)m_sentSize, s);

      availableWindow = AvailableWindow ();

      if (success < 0)
        {
          return -1;
        }

      NS_LOG_DEBUG ("AFTERAvailable Window " << AvailableWindow () <<
                    "Stream RWnd " << StreamWindow () <<
                    "BytesInFlight " << m_txBuffer->BytesInFlight () << "BufferedSize " << m_txBuffer->AppSize () <<
                    "MaxPacketSize " << (uint32_t)m_quicl5->GetMaxPacketSize ());

      ++nFrameSent;

    }

  if (nFrameSent > 0)
    {
      NS_LOG_INFO ("SendPendingData sent " << nFrameSent << " frames");
    }
  else
    {
      NS_LOG_INFO ("SendPendingData no frames sent");
    }

  return nFrameSent;
}

uint32_t
QuicStreamBase::SendDataFrame (SequenceNumber32 seq, uint32_t maxSize)
{
  NS_LOG_FUNCTION (this);

  if (m_streamStateSend == OPEN and (m_streamDirectionType == SENDER or m_streamDirectionType == BIDIRECTIONAL))
    {
      SetStreamStateSend (SEND);
    }

  Ptr<Packet> frame = m_txBuffer->NextSequence (maxSize, seq);

  bool lengthBit = true;

  QuicSubheader sub = QuicSubheader::CreateStreamSubHeader (m_streamId, (uint64_t)seq.GetValue (), frame->GetSize (), m_sentSize != 0, lengthBit, m_fin);
  m_sentSize += frame->GetSize ();

  frame->AddHeader (sub);
  int size = m_quicl5->Send (frame);
  if (size < 0)
    {
      frame->RemoveHeader (sub);
      m_txBuffer->Rejected (frame);
      NS_LOG_WARN ("Sending error - could not append packet to socket buffer. Putting packet back in stream buffer");
      m_sentSize -= frame->GetSize ();
    }
  else if (m_streamStateSend == SEND and m_fin and (m_streamDirectionType == SENDER or m_streamDirectionType == BIDIRECTIONAL))
    {
      SetStreamStateSend (DATA_SENT);
    }

  return size;
}

uint32_t
QuicStreamBase::AvailableWindow () const
{
  NS_LOG_FUNCTION (this);
  uint32_t streamRWnd = (m_streamId != 0) ? StreamWindow () : m_maxStreamData;
  return streamRWnd;
}

uint32_t
QuicStreamBase::StreamWindow () const
{
  NS_LOG_FUNCTION (this);
  uint32_t inFlight = m_txBuffer->BytesInFlight ();

  return (inFlight > m_maxStreamData) ? 0 : m_maxStreamData - inFlight;
}

int
QuicStreamBase::Recv (Ptr<Packet> frame, const QuicSubheader& sub, Address &address)
{
  NS_LOG_FUNCTION (this);

  uint8_t frameType = sub.GetFrameType ();

  switch (frameType)
    {

    case QuicSubheader::RST_STREAM:
      // TODO reset and close this stream
      if (m_streamId == 0)
        {
          m_quicl5->SignalAbortConnection (QuicSubheader::TransportErrorCodes_t::PROTOCOL_VIOLATION,
                                           "Received RST_STREAM in Stream 0");
          return -1;
        }

      if (!(m_streamDirectionType == RECEIVER or m_streamDirectionType == BIDIRECTIONAL))
        {
          m_quicl5->SignalAbortConnection (QuicSubheader::TransportErrorCodes_t::PROTOCOL_VIOLATION,
                                           "Received RST_STREAM in send-only Stream");
          return -1;
        }

      if ((m_streamStateRecv == DATA_READ or m_streamStateRecv == RESET_READ))
        {
          m_quicl5->SignalAbortConnection (QuicSubheader::TransportErrorCodes_t::PROTOCOL_VIOLATION,
                                           "Receiving RST_STREAM Frames in DATA_READ or RESET_READ Stream State");
          return -1;
        }

      if (m_fin and m_rxBuffer->GetFinalSize () != sub.GetOffset ())
        {
          m_quicl5->SignalAbortConnection (QuicSubheader::TransportErrorCodes_t::FINAL_OFFSET_ERROR,
                                           "RST_STREAM causes final offset to change for a Stream");
          return -1;
        }
      SetStreamStateRecvIf (m_streamStateRecv == RECV or m_streamStateSend == SIZE_KNOWN or m_streamStateSend == DATA_RECVD, RESET_RECVD);

      break;

    case QuicSubheader::MAX_STREAM_DATA:
      if (!(m_streamDirectionType == SENDER or m_streamDirectionType == BIDIRECTIONAL))
        {
          m_quicl5->SignalAbortConnection (QuicSubheader::TransportErrorCodes_t::PROTOCOL_VIOLATION,
                                           "Received MAX_STREAM_DATA in receive-only Stream");
          return -1;
        }
      else
        {
          SetMaxStreamData (sub.GetMaxStreamData ());
          NS_LOG_INFO ("Max stream data (flow control) - " << m_maxStreamData);
        }

      break;

    case QuicSubheader::STREAM_BLOCKED:
      // TODO block the stream
      if (!(m_streamDirectionType == RECEIVER or m_streamDirectionType == BIDIRECTIONAL))
        {
          m_quicl5->SignalAbortConnection (QuicSubheader::TransportErrorCodes_t::PROTOCOL_VIOLATION,
                                           "Received STREAM_BLOCKED in send-only Stream");
          return -1;
        }

      break;

    case QuicSubheader::STOP_SENDING:
      // TODO implement a mechanism to stop sending data
      if (!(m_streamDirectionType == SENDER or m_streamDirectionType == BIDIRECTIONAL))
        {
          m_quicl5->SignalAbortConnection (QuicSubheader::TransportErrorCodes_t::PROTOCOL_VIOLATION,
                                           "Received STOP_SENDING in receive-only Stream");
          return -1;
        }

      break;

    case QuicSubheader::STREAM000:
    case QuicSubheader::STREAM001:
    case QuicSubheader::STREAM010:
    case QuicSubheader::STREAM011:
    case QuicSubheader::STREAM100:
    case QuicSubheader::STREAM101:
    case QuicSubheader::STREAM110:
    case QuicSubheader::STREAM111:


      if (!(m_streamDirectionType == RECEIVER or m_streamDirectionType == BIDIRECTIONAL))
        {
          m_quicl5->SignalAbortConnection (QuicSubheader::TransportErrorCodes_t::PROTOCOL_VIOLATION,
                                           "Received STREAM in send-only Stream");
          return -1;
        }

      if (!(m_streamStateRecv == IDLE or m_streamStateRecv == RECV or m_streamStateRecv == SIZE_KNOWN))
        {
          m_quicl5->SignalAbortConnection (QuicSubheader::TransportErrorCodes_t::PROTOCOL_VIOLATION,
                                           "Received STREAM in State unequal to IDLE, RECV, SIZE_KNOWN");
          return -1;
        }

      if (m_rxBuffer->Size () + sub.GetLength () > m_maxStreamData)
        {
          m_quicl5->SignalAbortConnection (QuicSubheader::TransportErrorCodes_t::FLOW_CONTROL_ERROR,
                                           "Received more data w.r.t. Max Stream Data limit");
          return -1;
        }
      SetStreamStateRecvIf (m_streamStateRecv == IDLE, RECV);

      if (m_quicl5->ContainsTransportParameters () and m_streamId == 0)
        {
          QuicTransportParameters transport;
          // std::cout<<frame->ToString()<<"\n";
          // std::cout<<m_quicl5->ContainsTransportParameters ()<<"\n";
          frame->RemoveHeader (transport);
          m_quicl5->OnReceivedTransportParameters (transport);
        }
      
      if (m_fin and sub.IsStreamFin () and m_rxBuffer->GetFinalSize () != sub.GetOffset ())
        {
          m_quicl5->SignalAbortConnection (QuicSubheader::TransportErrorCodes_t::FINAL_OFFSET_ERROR,
                                           "STREAM causes final offset to change for a Stream");
          return -1;
        }

      m_fin = sub.IsStreamFin ();

      if (m_fin && m_streamId == 0)
        {
          m_quicl5->SignalAbortConnection (QuicSubheader::TransportErrorCodes_t::PROTOCOL_VIOLATION,
                                           "Received Stream FIN in Stream 0");
          return -1;
        }
      SetStreamStateRecvIf (m_streamStateRecv == RECV and m_fin, SIZE_KNOWN);

      //ywj
      if (firstRecvData2)
      {
        InitializeLogFiles ();
        firstRecvData2 = false;

        firstRecvTime2 = Simulator::Now ();
        firstSize2 = sub.GetLength ();
        totRecvSize += firstSize2;
      } 
      else
        {
          totRecvSize += sub.GetLength();
          double current_time = Simulator::Now ().GetSeconds();
          double time_duration = current_time - firstRecvTime.GetSeconds();
          double throughput = (totRecvSize - firstSize) * 8 / (time_duration * 1000);
          throughPutLog.open ("throughPutLog.txt", std::ios_base::out | std::ios_base::app);

                throughPutLog << std::setfill (' ') << std::setw (4) << Simulator::Now ().GetSeconds ()
                            << std::setfill (' ') << std::setw (21) << totRecvSize 
                            << std::setfill (' ') << std::setw (17) << time_duration
                            << std::setfill (' ') << std::setw (13) << throughput <<"\n";
                            
                throughPutLog.close();
        }

 std::cout<<Simulator::Now().GetSeconds()
          <<" QuicStreamBase::Recv "
          <<" Received a frame with the size " << sub.GetLength ()
          <<" expected offset: "<<m_recvSize
          <<" actual offset:"<<sub.GetOffset ()<<std::endl;

      //ywj: associate packetNumber in quic-socket-base.cc with the offset in quic-stream-base.cc
      SetCurrentOffset (sub.GetOffset());

           if (sub.GetOffset()==20278)
      {
        std::cout<<"hh";
      }


      if (m_streamId != 0)
        {
          recvList.insert(recvList.end(),sub.GetOffset());

          m_iniRecvTimeInfo.push_back (std::make_pair(sub.GetOffset(), Simulator::Now ().GetSeconds ()));

          arriveTimeLog.open("arriveTimeLog.txt", std::ofstream::out | std::ofstream::trunc); 
          
          arriveTimeLog << "FrameOffset\tArrival Time (s)\n";

          std::sort(m_iniRecvTimeInfo.begin(), m_iniRecvTimeInfo.end(), [](const std::pair<int,int> &left, const std::pair<int,int> &right) {return left.first < right.first;});
          for (auto irti:m_iniRecvTimeInfo)
            {
              arriveTimeLog << std::setfill (' ') << std::setw (4) << irti.first
              << std::setfill (' ') << std::setw (21) << irti.second <<"\n";
            }

          arriveTimeLog.close();


        }  

 
      if (m_recvSize == sub.GetOffset ()) 
        {
          SetLargestOffset (m_recvSize);
          NS_LOG_INFO ("Received a frame with the correct order of size " << sub.GetLength ());
         
          m_recvSize += sub.GetLength ();

          if (m_maxAdvertisedData == 0 || m_recvSize + m_rxBuffer->Available () > m_maxAdvertisedData + m_maxDataInterval)
            {
              m_maxAdvertisedData = m_recvSize + m_rxBuffer->Available ();
              QuicSubheader sub = QuicSubheader::CreateMaxData (m_recvSize + m_rxBuffer->Available ());
              // build empty packet
              Ptr<Packet> maxStream = Create<Packet> (0);
              maxStream->AddHeader (sub);
              m_quicl5->Send (maxStream);
            }

          NS_LOG_LOGIC ("Try to Flush RxBuffer if Available - offset " << m_recvSize);
          // check if the packets in the RX buffer can be released (in order release)
          std::pair<uint64_t, uint64_t> offSetLength = m_rxBuffer->GetDeliverable (m_recvSize);
          NS_LOG_LOGIC ("Extracting " << offSetLength.second << " bytes from RxBuffer");
          if (offSetLength.second > 0)
            {
              Ptr<Packet> payload = m_rxBuffer->Extract (offSetLength.second);
              sizeToRelease = offSetLength.second; //ywj: the amount of data exceeding the current m_recvSize is deliverable
              unOrderedSize -= sizeToRelease;   
              m_recvSize += offSetLength.second;

              if (payload) {
                frame->AddAtEnd (payload);
              }
            }

          if (m_streamId != 0)  //only count the received data packets
          {

            //ywj: goodput metric
            if (firstRecvData == true){
              firstRecvTime = Simulator::Now ();
              firstRecvData = false;
              firstSize = m_recvSize;
            }
            else{

              double current_time = Simulator::Now ().GetSeconds();
              double time_duration = current_time - firstRecvTime.GetSeconds();
              double goodput = (m_recvSize - firstSize) * 8 / (time_duration * 1000);

              goodputLog.open ("goodputLog.txt", std::ios_base::out | std::ios_base::app);

              goodputLog << std::setfill (' ') << std::setw (4) << current_time
                          << std::setfill (' ') << std::setw (21) << m_recvSize 
                          << std::setfill (' ') << std::setw (17) << time_duration
                          << std::setfill (' ') << std::setw (13) << goodput <<"\n";
                          
              goodputLog.close();

            }

            //ywj: recv_time metric 
            std::sort (recvList.begin (), recvList.end (), std::less<uint32_t> ());
            auto recv_it = recvList.begin();
            if (offSetLength.second > 0)
              {
                while (!recvList.empty() && *recv_it < sub.GetOffset() + sub.GetLength() + sizeToRelease)
                  {
                    m_offsetRecvTimeInfo.push_back (std::make_pair(*recv_it, Simulator::Now ().GetSeconds ()));
                    recvList.erase(recv_it);
                    recv_it = recvList.begin();
                  }
              }
            else 
              {
                m_offsetRecvTimeInfo.push_back (std::make_pair(sub.GetOffset(), Simulator::Now ().GetSeconds ()));
                recvList.erase(recvList.begin ());
              }
            //open the file for writing with the truncate-option, which means we'll clear the content before writing new data into it
            recvTimeLog.open("recvTimeLog.txt", std::ofstream::out | std::ofstream::trunc); 
            recvTimeLog << "FrameOffset\tSending Time (s)\n";

            std::sort(m_offsetRecvTimeInfo.begin(), m_offsetRecvTimeInfo.end(), [](const std::pair<int,int> &left, const std::pair<int,int> &right) {return left.first < right.first;});
            for (auto orti:m_offsetRecvTimeInfo)
              {
                recvTimeLog << std::setfill (' ') << std::setw (4) << orti.first
                << std::setfill (' ') << std::setw (21) << orti.second <<"\n";
              }

            recvTimeLog.close();


          }
          

          NS_LOG_LOGIC ("Flushed RxBuffer - new offset " << m_recvSize << ", " << m_rxBuffer->Available () << "bytes available");
          SetStreamStateRecvIf (m_streamStateRecv == SIZE_KNOWN and m_rxBuffer->Size () == 0, DATA_RECVD);

          if (m_streamId != 0 )
            {
              if (sub.GetMaxStreamData () > 0)
                {
                  SetMaxStreamData (sub.GetMaxStreamData ());
                  NS_LOG_LOGIC ("Received window set to offset " << sub.GetMaxStreamData ());
                }
              m_quicl5->Recv (frame, address);
            }
          else
            {
              NS_LOG_INFO ("Received handshake Message in Stream 0");
            }
          SetStreamStateRecvIf (m_streamStateRecv == DATA_RECVD, DATA_READ);

        }
      else
        {
          if (m_streamId != 0 && sub.GetMaxStreamData () > 0)
            {
              SetMaxStreamData (sub.GetMaxStreamData ());
              NS_LOG_LOGIC ("Received window set to offset " << sub.GetMaxStreamData ());
            }
          NS_LOG_INFO ("Buffering unordered received frame - offset " << m_recvSize << ", frame offset " << sub.GetOffset ());

          unOrderedSize += sub.GetLength();

          double current_time = Simulator::Now ().GetSeconds();

          auto result = TDisorderPair.find(current_time);
              if (result == TDisorderPair.end())   
              {
                  TDisorderPair.insert(std::pair<double, uint64_t> (current_time, unOrderedSize)); //if the pair doesn't exist, then add in
              }
              else
              {
                (*result).second = unOrderedSize;     //if already exist, then update the value of the key

                ofoLog.open ("ofoLog.txt", std::ios_base::out | std::ios_base::app);

                ofoLog << std::setfill (' ') << std::setw (4) << Simulator::Now ().GetSeconds ()
                            << std::setfill (' ') << std::setw (8) << TDisorderPair.at(current_time) <<"\n";
                            
                ofoLog.close();
              }


          if (m_recvSize > sub.GetOffset()) {
            // We've already gotten at least the beginning of this data.
            // TODO consider the possibility of receiving a retransmission 
            //  which has part of a previously received frame with new data appended to the end. 
            //  In that case we need to add just the new fragment to the buffer?

            uint64_t frameStart = sub.GetOffset();
            uint64_t frameEnd = sub.GetOffset() + sub.GetLength() - 1;

            NS_LOG_WARN (
              "Recv size greater than frame offset. Skipping unordered frame. Start: " << frameStart
              << "\tEnd: " << frameEnd << "\tRecv size: " << m_recvSize
              );
            if (frameEnd >= m_recvSize) 
              {
                // The frame contains the current offset position. This may indicate an issue
                // where retx packets have been merged. 
                NS_LOG_WARN ("Frame runs over the current offset position");
              }

            break;
          }

          // std::cout<<"QuicStreamBase::Recv---"
          //           <<" time: "<< Simulator::Now ().GetSeconds ()
          //           <<" total disorder bytes: "<< unOrderedSize<<std::endl;

          //std::cout<<"quic-stream-base.cc  Buffering unordered received frame of size " << sub.GetLength () <<" m_recvSize: "<<m_recvSize<< ", frame offset " << sub.GetOffset ()<<std::endl;
          if (!m_rxBuffer->Add (frame, sub) && frame->GetSize () > 0)
            {
              // Insert failed: No or duplicate data, or RX buffer full
              NS_LOG_WARN ("Dropping packet as it could not be inserted in RX buffer");
              if (frame->GetSize() > m_rxBuffer->Available()) {
                  // Abort connection if indeed buffer is full
                  m_quicl5->SignalAbortConnection (QuicSubheader::TransportErrorCodes_t::NO_ERROR, "Aborting connection due to full RX buffer");
              }
            }
        }

      break;

    default:

      NS_ABORT_MSG ("Received Corrupted Frame");
      break;
    }

  return 0;
}
// the following codes are cited from http://www.sfu.ca/~ntwooste/files/appendices_web.pdf

// void
// QuicStreamBase::PrintToFile (std::string newLine, uint64_t imsi)
// {
//  std::string filename = "goodPutLog.txt";
//  std::ofstream outFile;
//  if (firstWrite == true)
//  {
//     outFile.open (filename.c_str (), std::ios_base::out | std::ios_base::trunc);
//     if (!outFile.is_open ())
//     {
//       NS_LOG_ERROR ("Can't open file " << filename);
//       return;
//     }
//     firstWrite = false;
//     outFile << "time\tdeviceType\tstatus\tIMSI\tsourceCellID\ttargetCellID\tRNTI\tueCoordinates";
//     outFile << std::endl;
//  }
//  else
//  {
//     outFile.open (filename.c_str (), std::ios_base::out | std::ios_base::app);
//     if (!outFile.is_open ())
//     {
//       NS_LOG_ERROR ("Can't open file " << filename);
//       return;
//     }
//  }
//  outFile << newLine << "\t" << "(" << pos.x << ", " << pos.y << ")" << std::endl;
//  outFile.close ();
// }
// // UE connection established
// void
// QuicStreamBase::ueConnectionEstablished (uint64_t imsi, uint16_t cellId, uint16_t rnti)
// {
//  std::ostringstream newLine;
//  newLine << Simulator::Now ().GetSeconds () << "s\t" << "UE" << "\t" << "connection established"
//  << "\t" << imsi << "\t" << cellId << "\t" << "" << "\t" << rnti;
//  PrintToFile (newLine.str (), imsi);
// }

// void
// QuicStreamBase::CommandFlow (uint8_t type)
// {
//   NS_LOG_FUNCTION (this);

//   switch (type)
//     {

//     case QuicSubheader::RST_STREAM:
//       // TODO
//       NS_ABORT_MSG_IF (!(m_streamDirectionType == SENDER or m_streamDirectionType == BIDIRECTIONAL), " Sending RstStream Frames in Receiver Stream");
//       NS_ABORT_MSG_IF ((m_streamStateRecv == DATA_READ or m_streamStateRecv == RESET_READ or m_streamStateRecv == RESET_SENT), " Sending RstStream Frames in " << QuicStreamStateName[m_streamStateRecv] << " State");

//       SetStreamStateSendIf (m_streamStateSend == OPEN or m_streamStateSend == SEND or m_streamStateSend == DATA_SENT, RESET_SENT);
//       //	if((m_streamStateSend = OPEN or m_streamStateSend == SEND or m_streamStateSend == DATA_SENT)){SetStreamStateSend(RESET_SENT);}

//       break;

//     case QuicSubheader::MAX_STREAM_DATA:
//       // TODO
//       NS_ABORT_MSG_IF (!(m_streamDirectionType == RECEIVER or m_streamDirectionType == BIDIRECTIONAL), " Sending MaxStreamData Frame in Sender Stream");

//       break;

//     case QuicSubheader::STREAM_BLOCKED:
//       // TODO
//       NS_ABORT_MSG_IF (!(m_streamDirectionType == SENDER or m_streamDirectionType == BIDIRECTIONAL), " Sending StreamBlocked Frame in Receiver Stream");

//       break;

//     case QuicSubheader::STOP_SENDING:
//       // TODO
//       NS_ABORT_MSG_IF (!(m_streamDirectionType == RECEIVER or m_streamDirectionType == BIDIRECTIONAL), " Sending StopSending Frame in Sender Stream");

//       break;

//     default:
//       NS_ABORT_MSG ("Received Corrupted Command");
//       break;

//     }

// }

// bool 
// QuicStreamBase::ReplaceLastLine (std::ofstream fileout, std::ifstream filein)
// {
//     // string strReplace = "HELLO";
//     // string strNew = "GOODBYE";
//     // ifstream filein("filein.txt"); //File to read from
//     // ofstream fileout("fileout.txt"); //Temporary file
//     if(!filein || !fileout)
//     {
//         std::cout << "Error opening files!" << std::endl;
//         return 1;
//     }

//     std::string line;
//     while (filein >> std::ws && std::getline(filein, line)) // skip empty lines
//         ;

//     std::regex regex{R"([\s,]+)"}; // split on space and comma
//     std::sregex_token_iterator it{line.begin(), line.end(), regex, -1};
//     std::vector<std::string> words{it, {}};

//     if (atof(words[0].c_str()) == )

//     string strTemp;
//     //bool found = false;
//     while(filein >> strTemp)
//     {
//         if(strTemp == strReplace){
//             strTemp = strNew;
//             //found = true;
//         }
//         strTemp += "\n";
//         fileout << strTemp;
//         //if(found) break;
//     }
//     return 0;
// }

//ywj
std::string 
QuicStreamBase::LogFileName(const std::string& logSuffix) {
  // return mpquicLogDirectory + logSuffix + ".txt";
  return logSuffix + ".txt";
}

void
QuicStreamBase::SetCurrentOffset (uint32_t offSet)
{
  NS_LOG_FUNCTION (this);

  m_currentOffset = offSet;

}


uint32_t
QuicStreamBase::GetCurrentOffset ()
{
  NS_LOG_FUNCTION (this);

  return m_currentOffset;

}

void
QuicStreamBase::SetLargestOffset (uint32_t offSet)
{
  NS_LOG_FUNCTION (this);

  m_largeOffset = offSet;

}

uint32_t
QuicStreamBase::GetLargestOffset ()
{
  NS_LOG_FUNCTION (this);

  return m_largeOffset;

}


void
QuicStreamBase::InitializeLogFiles ()
{
  NS_LOG_FUNCTION (this);
  // std::string gLog = LogFileName("goodputLog");
  // goodputLog.open (gLog.c_str ());
  goodputLog.open ("goodputLog.txt");
  goodputLog << "Time\tIn_Order_Size (bytes)\tTime_Duration (s)\tGoodput (Kbps)\n";
  //goodputLog.flush ();

  ofoLog.open ("ofoLog.txt");
  ofoLog << "Time\tOFO\n";
  //ofoLog.flush ();

  throughPutLog.open("throughPutLog.txt");
  throughPutLog << "Time\tIn_Order_Size (bytes)\tTime_Duration (s)\tThroughput (Kbps)\n";


}

uint32_t
QuicStreamBase::SendMaxStreamData ()
{
  return m_recvSize + m_rxBuffer->Available ();
}

void
QuicStreamBase::SetMaxStreamData (uint32_t maxStreamData)
{
  NS_LOG_FUNCTION (this << maxStreamData);
  NS_LOG_DEBUG ("Update max stream data from " << m_maxStreamData << " to " << maxStreamData);
  m_maxStreamData = maxStreamData;
}

uint32_t
QuicStreamBase::GetMaxStreamData () const
{
  return m_maxStreamData;
}

void
QuicStreamBase::SetStreamDirectionType (const QuicStreamDirectionTypes_t& streamDirectionType)
{
  NS_LOG_FUNCTION (this);
  m_streamDirectionType = streamDirectionType;
}

QuicStream::QuicStreamDirectionTypes_t
QuicStreamBase::GetStreamDirectionType ()
{
  return m_streamDirectionType;
}

void
QuicStreamBase::SetStreamType (const QuicStreamTypes_t& streamType)
{
  NS_LOG_FUNCTION (this);
  m_streamType = streamType;
}

void
QuicStreamBase::SetStreamStateSend (const QuicStreamStates_t& streamState)
{
  NS_LOG_FUNCTION (this);

  if (m_streamType == SERVER_INITIATED_BIDIRECTIONAL or m_streamType == SERVER_INITIATED_UNIDIRECTIONAL)
    {

      NS_LOG_INFO ("Server Stream " << QuicStreamStateName[m_streamStateSend] << " -> " << QuicStreamStateName[streamState] << "");

    }
  else
    {

      NS_LOG_INFO ("Client Stream " << QuicStreamStateName[m_streamStateSend] << " -> " << QuicStreamStateName[streamState] << "");

    }

  m_streamStateSend = streamState;
}

void
QuicStreamBase::SetStreamStateSendIf (bool condition, const QuicStreamStates_t& streamState)
{
  NS_LOG_FUNCTION (this);
  if (condition)
    {
      SetStreamStateSend (streamState);
    }
}


void
QuicStreamBase::SetStreamStateRecv (const QuicStreamStates_t& streamState)
{
  NS_LOG_FUNCTION (this);

  if (m_streamType == SERVER_INITIATED_BIDIRECTIONAL or m_streamType == SERVER_INITIATED_UNIDIRECTIONAL)
    {

      NS_LOG_INFO ("Server Stream " << QuicStreamStateName[m_streamStateRecv] << " -> " << QuicStreamStateName[streamState] << "");

    }
  else
    {

      NS_LOG_INFO ("Client Stream " << QuicStreamStateName[m_streamStateRecv] << " -> " << QuicStreamStateName[streamState] << "");

    }

  m_streamStateRecv = streamState;
}

void
QuicStreamBase::SetStreamStateRecvIf (bool condition, const QuicStreamStates_t& streamState)
{
  NS_LOG_FUNCTION (this);
  if (condition)
    {
      SetStreamStateRecv (streamState);
    }
}

void
QuicStreamBase::SetNode (Ptr<Node> node)
{
  NS_LOG_FUNCTION (this);
  m_node = node;
}

void
QuicStreamBase::SetStreamId (uint64_t streamId)
{
  NS_LOG_FUNCTION (this);
  m_streamId = streamId;

  uint64_t mask = 0x00000003;

  switch (m_streamId & mask)
    {

    case 0:
      SetStreamType (QuicStream::CLIENT_INITIATED_BIDIRECTIONAL);
      break;
    case 1:
      SetStreamType (QuicStream::SERVER_INITIATED_BIDIRECTIONAL);
      break;
    case 2:
      SetStreamType (QuicStream::CLIENT_INITIATED_UNIDIRECTIONAL);
      break;
    case 3:
      SetStreamType (QuicStream::SERVER_INITIATED_UNIDIRECTIONAL);
      break;
    }

}

uint64_t
QuicStreamBase::GetStreamId (void)
{
  return m_streamId;
}

void
QuicStreamBase::SetConnectionId (uint64_t connId)
{
  NS_LOG_FUNCTION (this << connId);
  m_connectionId = connId;
}

std::string
QuicStreamBase::StreamDirectionTypeToString () const
{
  static const char* StreamDirectionTypeNames[6] = {
    "SENDER",
    "RECEIVER",
    "BIDIRECTIONAL",
    "UNKNOWN"
  };

  std::string typeDescription = "";

  typeDescription.append (StreamDirectionTypeNames[m_streamDirectionType]);

  return typeDescription;
}

void
QuicStreamBase::SetStreamSndBufSize (uint32_t size)
{
  NS_LOG_FUNCTION (this << size);
  m_streamTxBufferSize = size;
  m_txBuffer->SetMaxBufferSize (size);
}

uint32_t
QuicStreamBase::GetStreamSndBufSize (void) const
{
  return m_txBuffer->GetMaxBufferSize ();
}

void
QuicStreamBase::SetStreamRcvBufSize (uint32_t size)
{
  NS_LOG_FUNCTION (this << size);
  m_streamRxBufferSize = size;
  m_rxBuffer->SetMaxBufferSize (size);
}

uint32_t
QuicStreamBase::GetStreamRcvBufSize (void) const
{
  return m_rxBuffer->GetMaxBufferSize ();
}

} // namespace ns3