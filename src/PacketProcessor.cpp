#include "PacketProcessor.h"
#include <vector>
#include <algorithm>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

std::unordered_map<std::string, int> PacketProcessor::dst_ips;
std::unordered_map<std::string, int> PacketProcessor::proto_counts;

PacketProcessor::PacketProcessor(std::string& filename)
{
    this->filename = filename;
    this->packet_count = 0;
    this->total_size = 0;

    proto_counts.insert(std::pair<std::string, int> ("TCP", 0));
    proto_counts.insert(std::pair<std::string, int> ("UDP", 0));
    proto_counts.insert(std::pair<std::string, int> ("ICMP", 0));
}

void PacketProcessor::process_packets()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(filename.c_str(), errbuf);
    
    struct pcap_pkthdr* header;
    
    if (pcap_loop(handle, 0, packet_handler, reinterpret_cast<u_char*>(this)) < 0)
    {

    }

}


void PacketProcessor::packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    PacketProcessor* processor = reinterpret_cast<PacketProcessor*>(user_data);
    
    processor->packet_count++;
    processor->total_size += pkthdr->len;

    const struct ether_header *eth_header = (struct ether_header *) packet;
    const struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));

    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

    std::string dst_ip_str(dst_ip);

    auto iterator = processor->dst_ips.find(dst_ip_str);
    if (iterator == processor->dst_ips.end())
    {
        processor->dst_ips[dst_ip_str] = 1;
    } else {
        processor->dst_ips[dst_ip_str] ++;
    }

    switch (ip_header->ip_p)
    {
        case IPPROTO_TCP:
            processor->proto_counts["TCP"] ++;
            break;
        case IPPROTO_UDP:
            processor->proto_counts["UDP"] ++;
            break;
        case IPPROTO_ICMP:
            processor->proto_counts["ICMP"] ++;
            break;
        default:
            processor->proto_counts["other"] ++;
            break;
    }
}

uint32_t PacketProcessor::get_average_size()
{
    return total_size / packet_count;
}

uint32_t PacketProcessor::get_total_volume()
{
    return total_size;
}

std::vector<std::string> PacketProcessor::get_dst_ips()
{
    std::vector<std::pair<std::string, int>> pairs;
    std::vector<std::string> ordered_dst_ips;

    for (const auto& iterator : dst_ips)
    {
        pairs.push_back(iterator);
    }

    sort(pairs.begin(), pairs.end(), [](const auto& a, const auto& b) {
        return a.second > b.second;
    });
    
    for (const auto& iterator : pairs)
    {
        ordered_dst_ips.push_back(iterator.first);
    }

    return ordered_dst_ips;
}

std::vector<std::pair<std::string, int>> PacketProcessor::get_proto_counts()
{
    std::vector<std::pair<std::string, int>> pairs;

    for (const auto& iterator : proto_counts)
    {
        pairs.push_back(iterator);
    }

    return pairs;
}

