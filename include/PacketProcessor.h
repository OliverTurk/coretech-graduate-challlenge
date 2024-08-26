#ifndef PACKET_PROCESSOR_H
#define PACKET_PROCESSOR_H

#include <iostream>
#include <unordered_map>

class PacketProcessor
{
public:
    PacketProcessor(std::string& filename);

    void process_packets();
    int get_packet_count();
    uint32_t get_average_size();
    uint32_t get_total_volume();
    std::vector<std::string> get_dst_ips();
    std::vector<std::pair<std::string, int>> get_proto_counts();

private:
    static void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);

    static std::unordered_map<std::string, int> dst_ips;
    static std::unordered_map<std::string, int> proto_counts;

    std::string filename;
    int packet_count;
    uint32_t total_size;
};

#endif
