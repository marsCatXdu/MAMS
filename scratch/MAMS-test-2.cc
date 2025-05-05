#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/quic-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/config-store-module.h"
#include "ns3/random-variable-stream.h"
#include <iostream>
#include "ns3/flow-monitor-module.h"
#include "ns3/gnuplot.h"
#include "ns3/quic-socket-base.h"

#include <stdlib.h>
#include <unistd.h>

#include <boost/assign/list_of.hpp>

#include <iostream>
#include <string>
#include <regex>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("quic-tester");


static void CwndChange(Ptr<OutputStreamWrapper> stream, uint32_t oldCwnd, uint32_t newCwnd)
{
    *stream->GetStream() << Simulator::Now().GetSeconds() << "\t" << oldCwnd << "\t" << newCwnd << std::endl;
}


static void RttChange(Ptr<OutputStreamWrapper> stream, Time oldRtt, Time newRtt)
{
    *stream->GetStream() << Simulator::Now().GetSeconds() << "\t" << oldRtt.GetSeconds() << "\t" << newRtt.GetSeconds() << std::endl;
}


static void Traces(uint32_t serverId, std::string pathVersion, std::string finalPart)
{
    AsciiTraceHelper asciiTraceHelper;

    std::ostringstream pathCW;
    pathCW << "/NodeList/" << serverId << "/$ns3::QuicL4Protocol/SocketList/*/QuicSocketBase/CongestionWindow";
    NS_LOG_INFO("Matches cw " << Config::LookupMatches(pathCW.str().c_str()).GetN());

    std::ostringstream path0CW;
    path0CW << "/NodeList/" << serverId << "/$ns3::QuicL4Protocol/SocketList/*/QuicSocketBase/SubflowWindow0";
    NS_LOG_INFO("Matches cw " << Config::LookupMatches(path0CW.str().c_str()).GetN());

    std::ostringstream path1CW;
    path1CW << "/NodeList/" << serverId << "/$ns3::QuicL4Protocol/SocketList/*/QuicSocketBase/SubflowWindow1";
    NS_LOG_INFO("Matches cw " << Config::LookupMatches(path1CW.str().c_str()).GetN());

    std::ostringstream fileCW;
    fileCW << pathVersion << "QUIC-cwnd-change"  << serverId << "" << finalPart;
    std::ostringstream file0CW;
    file0CW << pathVersion << "QUIC-cwnd-change-p0-"  << serverId << "" << finalPart;
    std::ostringstream file1CW;
    file1CW << pathVersion << "QUIC-cwnd-change-p1-"  << serverId << "" << finalPart;

    std::ostringstream path0rtt;
    path0rtt << "/NodeList/" << serverId << "/$ns3::QuicL4Protocol/SocketList/*/QuicSocketBase/RTT0";

    std::ostringstream path1rtt;
    path1rtt << "/NodeList/" << serverId << "/$ns3::QuicL4Protocol/SocketList/*/QuicSocketBase/RTT1";

    std::ostringstream file0rtt;
    file0rtt << pathVersion << "QUIC-rtt-change-p0-"  << serverId << "" << finalPart;
    std::ostringstream file1rtt;
    file1rtt << pathVersion << "QUIC-rtt-change-p1-"  << serverId << "" << finalPart;

    Ptr<OutputStreamWrapper> stream = asciiTraceHelper.CreateFileStream(fileCW.str().c_str());
    Config::ConnectWithoutContext(pathCW.str().c_str(), MakeBoundCallback(&CwndChange, stream));

    Ptr<OutputStreamWrapper> stream0 = asciiTraceHelper.CreateFileStream(file0CW.str().c_str());
    Config::ConnectWithoutContext(path0CW.str().c_str(), MakeBoundCallback(&CwndChange, stream0));

    Ptr<OutputStreamWrapper> stream1 = asciiTraceHelper.CreateFileStream(file1CW.str().c_str());
    Config::ConnectWithoutContext(path1CW.str().c_str(), MakeBoundCallback(&CwndChange, stream1));

    Ptr<OutputStreamWrapper> stream0rtt = asciiTraceHelper.CreateFileStream (file0rtt.str().c_str());
    Config::ConnectWithoutContext(path0rtt.str().c_str(), MakeBoundCallback(&RttChange, stream0rtt));

    Ptr<OutputStreamWrapper> stream1rtt = asciiTraceHelper.CreateFileStream (file1rtt.str().c_str());
    Config::ConnectWithoutContext(path1rtt.str().c_str(), MakeBoundCallback(&RttChange, stream1rtt));
}


std::vector<uint32_t> RxBytesList = boost::assign::list_of(0)(0);


/**
 * Read FlowMonitor data every second and update gnuplot data Gnuplot2dDataset
 */
void ThroughputMonitor(FlowMonitorHelper *fmhelper, Ptr<FlowMonitor> flowMon, Gnuplot2dDataset DataSet, Gnuplot2dDataset DataSet1)
{
    std::map<FlowId, FlowMonitor::FlowStats> flowStats = flowMon->GetFlowStats();
    Ptr<Ipv4FlowClassifier> classing = DynamicCast<Ipv4FlowClassifier> (fmhelper->GetClassifier());
    for (std::map<FlowId, FlowMonitor::FlowStats>::const_iterator stats = flowStats.begin (); stats != flowStats.end (); ++stats)
    {
        // updata gnuplot data
        if(stats->first == 1) {
            DataSet.Add((double)(Simulator::Now().GetSeconds()-1),(double)(stats->second.rxBytes-RxBytesList[0])*8/1024/1024*10);
            RxBytesList[0] = stats->second.rxBytes;
        }
        if(stats->first == 3) {
            DataSet1.Add((double)(Simulator::Now().GetSeconds()-1),(double)(stats->second.rxBytes-RxBytesList[1])*8/1024/1024*10);
            RxBytesList[1] = stats->second.rxBytes;
        }
    }
    Simulator::Schedule(Seconds(0.1),&ThroughputMonitor, fmhelper, flowMon, DataSet, DataSet1);
}


void ModifyLinkRate(NetDeviceContainer *ptp, QuicEchoClientHelper echoClient, DataRate lr, uint8_t subflowId)
{
    StaticCast<PointToPointNetDevice>(ptp->Get(0))->SetDataRate(lr);
    if(subflowId == 0) {
        echoClient.SetBW0(lr);
    } else if (subflowId == 1) {
        echoClient.SetBW1(lr);
    } else {
        std::cout<<"subflowId may be wrong!!!"<<std::endl;
    }
}


/**
 * Outline:
 *   1. Create 2 nodes
 *   2. Install QUIC stack (QuicHelper)
 *   3. Create 2 p2p links, attach error model
 *   4. Install echo apps
 *   5. Schedule monitoring & mobility events
 *   6. Run 50s
 */
int main (int argc, char *argv[])
{
    Time::SetResolution(Time::NS);
    LogComponentEnableAll(LOG_PREFIX_TIME);
    LogComponentEnableAll(LOG_PREFIX_FUNC);
    LogComponentEnableAll(LOG_PREFIX_NODE);

    bool isMob = true;
    bool randMob = false;
    std::vector<std::string> rate(2);
    std::vector<std::string> delay(2);
    std::vector<NetDeviceContainer> netDevices(2);
    std::string dataRate0 = "10Mbps";
    std::string delay1 = "10ms";
    delay[0] = "10ms";
    rate[1] = "50Mbps";

    double errorRate = 0.000004;
    uint8_t schAlgo = 3;
    std::string maxBuffSize = "5p";
    uint64_t fileSize = 8e6;

    CommandLine cmd;
    cmd.Usage("Simulation of bulkSend over MPQUIC.\n");
    cmd.AddValue("isMob", "mobility scenario", isMob);
    cmd.AddValue("randMob", "mobility pattern", randMob);
    cmd.AddValue("errorRate", "The percentage of packets that should be lost, expressed as a double where 1 == 100%", errorRate);
    cmd.AddValue("fileSize", "file size", fileSize);
    cmd.AddValue("delay1", "The initial delay for path1", delay1);
    cmd.AddValue("dataRate0", "The data rate for path 0", dataRate0);
    cmd.AddValue("maxBuffSize", "max buffer size of router", maxBuffSize);
    cmd.AddValue("schAlgo", "mutipath scheduler algorithm", schAlgo); // 2, mpquic-rr, 3. MAMS, 5. LATE

    cmd.Parse (argc, argv);

    rate[0] = dataRate0;
    delay[1] = delay1;

    Config::SetDefault("ns3::QuicStreamBase::StreamSndBufSize",UintegerValue(10485760));
    Config::SetDefault("ns3::QuicStreamBase::StreamRcvBufSize",UintegerValue(10485760));
    Config::SetDefault("ns3::QuicSocketBase::SocketSndBufSize",UintegerValue(10485760));
    Config::SetDefault("ns3::QuicSocketBase::SocketRcvBufSize",UintegerValue(10485760));

    Config::SetDefault("ns3::MpQuicSubFlow::delay", DoubleValue (0.03));
    Config::SetDefault("ns3::DropTailQueue<Packet>::MaxSize", StringValue (maxBuffSize));

    NodeContainer nodes;
    nodes.Create(2);
    auto n1 = nodes.Get(0);
    auto n2 = nodes.Get(1);

    int sf = 2;
    Time simulationEndTime = Seconds(9);

    int start_time = 1;

    QuicHelper stack;
    stack.InstallQuic (nodes);

    float delayInt[2];
    for(uint32_t i = 0; i < delay.size(); i++) {
        std::stringstream ss(delay[i]);
        for(uint32_t j = 0; ss >> j; ) {
            delayInt[i] = (float)j / 1000;
        }
    }

    float bwInt[2];
    for(uint32_t i = 0; i < rate.size(); i++) {
        std::stringstream ss(rate[i]);
        for(int j = 0; ss >> j; ) {
            bwInt[i] = (float)j;
        }
    }

    std::vector<Ipv4InterfaceContainer> ipv4Ints;

    Ptr<RateErrorModel> em1 = CreateObjectWithAttributes<RateErrorModel>("RanVar",
                                                                         StringValue("ns3::UniformRandomVariable[Min=0.0|Max=1.0]"),
                                                                         "ErrorRate",
                                                                         DoubleValue (errorRate));

    for(int i=0; i < sf; i++) {
        // Creation of the point to point link between hots
        PointToPointHelper p2plink;
        p2plink.SetDeviceAttribute ("DataRate", StringValue(rate[i]));
        p2plink.SetChannelAttribute("Delay", StringValue(delay[i]));

        netDevices[i] = p2plink.Install(nodes);
        netDevices[i].Get (1)->SetAttribute ("ReceiveErrorModel", PointerValue (em1));

        std::cout << "netdevice 0 "<<netDevices[i].Get(0) <<"netdevice 1 "<<netDevices[i].Get(1) << std::endl;

        // Attribution of the IP addresses
        std::stringstream netAddr;
        netAddr << "10.1." << (i+1) << ".0";
        std::string str = netAddr.str();

        Ipv4AddressHelper ipv4addr;
        ipv4addr.SetBase(str.c_str(), "255.255.255.0");
        Ipv4InterfaceContainer interface = ipv4addr.Assign(netDevices[i]);
        ipv4Ints.insert(ipv4Ints.end(), interface);

        p2plink.EnablePcap("prueba" , nodes, false);
    }

    for(auto ipaddr:ipv4Ints) {
        std::cout<<"ipaddr0: "<<ipaddr.GetAddress(0)<<" ipaddr1: "<<ipaddr.GetAddress(1);
    }

    uint8_t dlPort = 9;

    QuicEchoServerHelper echoServer(dlPort);

    ApplicationContainer serverApps = echoServer.Install(nodes.Get(1));
    serverApps.Start(Seconds(0.0));
    serverApps.Stop(simulationEndTime);

    //QuicEchoClientHelper echoClient (ground_station_interfaces[1].GetAddress(0), 9);
    //for our multipath scenario, there are 4 interfaces in total, [0],[1] are for gs1; [2],[3] are for gs2
    QuicEchoClientHelper echoClient(ipv4Ints[0].GetAddress(1), dlPort);
    echoClient.SetAttribute("MaxPackets", UintegerValue(1));
    echoClient.SetAttribute("Interval", TimeValue (Seconds(0.01)));
    echoClient.SetAttribute("PacketSize", UintegerValue(1460));
    echoClient.SetIniRTT0(Seconds(delayInt[0]));
    echoClient.SetIniRTT1(Seconds(delayInt[1]));
    echoClient.SetER(errorRate);
    echoClient.SetBW0(DataRate(rate[0]));
    echoClient.SetBW1(DataRate(rate[1]));
    echoClient.SetScheAlgo(schAlgo);
    echoClient.WithMobility(isMob);

    ApplicationContainer clientApps = echoClient.Install(nodes.Get(0));
    echoClient.SetFill(clientApps.Get(0), 100, fileSize);
    clientApps.Start(Seconds(start_time));
    clientApps.Stop(simulationEndTime);

    Simulator::Schedule(Seconds(start_time+0.0000001), &Traces, n2->GetId(), "./server", ".txt");
    Simulator::Schedule(Seconds(start_time+0.0000001), &Traces, n1->GetId(), "./client", ".txt");

    Packet::EnablePrinting();
    Packet::EnableChecking();

    std::string fileNameWithNoExtension = "FlowVSThroughput_";
    std::string graphicsFileName        = fileNameWithNoExtension + ".png";
    std::string plotFileName            = fileNameWithNoExtension + ".plt";
    std::string plotTitle               = "Throughput vs Time";
    std::string dataTitle               = "path 0";
    std::string dataTitle1              = "path 1";

    // Instantiate the plot and set its title.
    Gnuplot gnuplot(graphicsFileName);
    gnuplot.SetTitle(plotTitle);

    // Make the graphics file, which the plot file will be when it is used with Gnuplot, be a PNG file.
    gnuplot.SetTerminal("png");

    // Set the labels for each axis.
    gnuplot.SetLegend("Time(s)", "Throughput(Mbps)");

    Gnuplot2dDataset dataset;
    dataset.SetTitle(dataTitle);
    dataset.SetStyle(Gnuplot2dDataset::LINES_POINTS);
    Gnuplot2dDataset dataset1;
    dataset1.SetTitle(dataTitle1);
    dataset1.SetStyle(Gnuplot2dDataset::LINES_POINTS);
    FlowMonitorHelper flowmon;
    Ptr<FlowMonitor> monitor = flowmon.InstallAll();
    ThroughputMonitor(&flowmon, monitor, dataset, dataset1);

    if(isMob) {
        (void)bwInt;
        Simulator::Schedule(Seconds(0), &ModifyLinkRate, &netDevices[0], echoClient, DataRate("1Mbps"), 0);
        Simulator::Schedule(Seconds(1), &ModifyLinkRate, &netDevices[0], echoClient, DataRate("5Mbps"), 0);
        Simulator::Schedule(Seconds(2), &ModifyLinkRate, &netDevices[0], echoClient, DataRate("5Mbps"), 0);
        Simulator::Schedule(Seconds(3), &ModifyLinkRate, &netDevices[0], echoClient, DataRate("10Mbps"), 0);
        // Simulator::Schedule(Seconds(4), &ModifyLinkRate, &netDevices[0], echoClient, DataRate("15Mbps"), 0);
        Simulator::Schedule(Seconds(0), &ModifyLinkRate, &netDevices[1], echoClient, DataRate("13Mbps"), 1);
        Simulator::Schedule(Seconds(1), &ModifyLinkRate, &netDevices[1], echoClient, DataRate("8Mbps"), 1);
        Simulator::Schedule(Seconds(2), &ModifyLinkRate, &netDevices[1], echoClient, DataRate("5Mbps"), 1);
        Simulator::Schedule(Seconds(3), &ModifyLinkRate, &netDevices[1], echoClient, DataRate("3Mbps"), 1);
        Simulator::Schedule(Seconds(4), &ModifyLinkRate, &netDevices[1], echoClient, DataRate("2Mbps"), 1);
        // for(int i = 0; i < 50; i++) {
        //     for(int j = 1; j < 5; j++) {
        //         //after the rtt of each path, modify the data rate
        //         Simulator::Schedule(Seconds(start_time+(i*4+j+1)*delayInt[0]*2), &ModifyLinkRate, &netDevices[0], echoClient, DataRate(std::to_string(bwInt[0]-j*(bwInt[0]/5))+"Mbps"), 0);
        //         Simulator::Schedule(Seconds(start_time+(i*4+j+1)*delayInt[1]*2), &ModifyLinkRate, &netDevices[1], echoClient, DataRate(std::to_string(bwInt[0]/5*(j+1))+"Mbps"), 1);
        //     }
        // }

        // for(int i = 0; i < 50; i++) {
        //     for(int j = 1; j < 5; j++) {
        //         if(randMob) {
        //             Ptr<ns3::NormalRandomVariable> rate = CreateObject<NormalRandomVariable>();
        //             rate->SetAttribute("Mean", DoubleValue(bwInt[0]));
        //             rate->SetAttribute("Variance", DoubleValue(bwInt[0]/10));
        //             Simulator::Schedule(Seconds(start_time + (i*4 + j + 1) * delayInt[0] * 2), &ModifyLinkRate, &netDevices[0], echoClient, DataRate(std::to_string(rate->GetValue())+"Mbps"), 0);
        //             rate->SetAttribute("Mean", DoubleValue(bwInt[1]));
        //             rate->SetAttribute("Variance", DoubleValue(bwInt[1]/10));
        //             Simulator::Schedule(Seconds(start_time + (i*4 + j + 1) * delayInt[1] * 2), &ModifyLinkRate, &netDevices[1], echoClient, DataRate(std::to_string(rate->GetValue())+"Mbps"), 1);
        //         } else{
        //             //after the rtt of each path, modify the data rate
        //             Simulator::Schedule(Seconds(start_time+(i*4+j+1)*delayInt[0]*2), &ModifyLinkRate, &netDevices[0], echoClient, DataRate(std::to_string(bwInt[0]-j*(bwInt[0]/5))+"Mbps"), 0);
        //             // std::cout<<"time: "<< start_time + (i * 4 + j) * delayInt[0] * 2 <<" path0 : rate "<<bwInt[0]-j*(bwInt[0]/5)<<"Mbps"<<"\n";
        //             Simulator::Schedule(Seconds (start_time + (i * 4 + j + 1) * delayInt[1] * 2), &ModifyLinkRate, &netDevices[1], echoClient, DataRate(std::to_string(bwInt[0]/5*(j+1))+"Mbps"), 1);
        //             // std::cout<<"time: "<< start_time + (i * 4 + j) * delayInt[1] * 2 <<" path1 : rate "<<bwInt[0]/5*(j+1)<<"Mbps"<<"\n";
        //         }
        //     }
        // }
    }


    Simulator::Stop(simulationEndTime);

    std::cout << "\n\n#################### STARTING RUN ####################\n\n";
    Simulator::Run();

    //Gnuplot ...continued
    gnuplot.AddDataset(dataset);
    gnuplot.AddDataset(dataset1);

    dataset.Add(0,0);
    dataset.Add(0,0);
    // Open the plot file.
    std::ofstream plotFile(plotFileName.c_str());
    // Write the plot file.
    gnuplot.GenerateOutput(plotFile);
    // Close the plot file.
    plotFile.close();

    flowmon.SerializeToXmlFile("flow", false, false);

    monitor->CheckForLostPackets ();
    Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier> (flowmon.GetClassifier ());
    FlowMonitor::FlowStatsContainer stats = monitor->GetFlowStats ();

    std::ofstream outfile;
    outfile.open("wmp"+std::to_string(simulationEndTime.GetSeconds())+".txt");
    for (std::map<FlowId, FlowMonitor::FlowStats>::const_iterator i = stats.begin (); i != stats.end (); ++i) {
        Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow (i->first);
        outfile << "Flow " << i->first  << " (" << t.sourceAddress << " -> " << t.destinationAddress << ")\n";
        outfile << "  Tx Packets: " << i->second.txPackets << "\n";
        outfile << "  Tx Bytes:   " << i->second.txBytes << "\n";
        outfile << "  TxOffered:  " << i->second.txBytes * 8.0 / simulationEndTime.GetSeconds () / 1000 / 1000  << " Mbps\n";
        outfile << "  Rx Packets: " << i->second.rxPackets << "\n";
        outfile << "  Rx Bytes:   " << i->second.rxBytes << "\n";
        outfile << "  Throughput: " << i->second.rxBytes * 8.0 / simulationEndTime.GetSeconds () / 1000 / 1000  << " Mbps\n";
        outfile << "  Tx time: " << i->second.timeLastTxPacket - i->second.timeFirstTxPacket<<"\n";
        outfile << "  Rx time: " << i->second.timeLastRxPacket - i->second.timeFirstRxPacket<<"\n";
        outfile << "delay sum" << i->second.delaySum<<"\n";
        std::cout  <<  "  Tx Bytes:   " << i->second.txBytes << "\n";
        std::cout << "  Throughput: " << i->second.rxBytes * 8.0 / simulationEndTime.GetSeconds () / 1000 / 1000  << " Mbps\n";
        std::cout <<  "  Tx time: " << (i->second.timeLastTxPacket - i->second.timeFirstTxPacket).GetSeconds()<<"\n";
    }

    outfile.close();
    // std::cout << "\n\n#################### RUN FINISHED ####################\n\n\n";
    Simulator::Destroy ();

    // Ptr<PacketSink> sink1 = DynamicCast<PacketSink> (sinkApps.Get (0));
    // std::cout << "Total Bytes Received: " << sink1->GetTotalRx () << std::endl;
    // std::cout << "\n\n#################### SIMULATION END ####################\n\n\n";
    return 0;
}


