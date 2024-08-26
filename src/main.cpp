#include "PacketProcessor.h"
#include <pcap.h>
#include <vector>
#include <iostream>
#include <fstream>

void generate_output_file(PacketProcessor &processor);

int main(int argc, char *argv[])
{ 
    std::cout << "Program started" << std::endl;

    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <pcap_file>" << std::endl;
        return 1;
    }

    char *filename(argv[1]);

    std::string filename_str = std::string(filename);

    PacketProcessor processor(filename_str);
    
    processor.process_packets();

    generate_output_file(processor);

    return 0; 
}

void generate_output_file(PacketProcessor &processor)
{
    
    std::ofstream outfile("output.txt");

    if (outfile.is_open())
    {
        outfile << "Average packet size: " << processor.get_average_size() << "B" << std::endl;
        outfile << "Total volume: " << processor.get_total_volume() << "B" <<std::endl;
        
        outfile << "Transport protocol frequencies" << std::endl;

        for (const auto& protocol : processor.get_proto_counts())
        {
            outfile << protocol.first << ": " << protocol.second << std::endl;
        }

        outfile << "Destination IPs:" << std::endl;
        
        for (const auto& ip : processor.get_dst_ips())
        {
            outfile << ip << std::endl;
        }

        outfile.close();

        std::cout << "Output written to output.txt" << std::endl;
    }
}


