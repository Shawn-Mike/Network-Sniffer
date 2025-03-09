// Compile with: gcc Capturepacket.c -o capturepacket -lpcap
// will need to elevate to sudo or add user to new pcap group

#include <stdio.h>
#include <time.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header);

int main(int argc, char *argv[]) {
    char error_buffer[PCAP_ERRBUF_SIZE]; //defined in pcap.h
    pcap_if_t *all_devs, *device;
    pcap_t *handle;
    const u_char *packet;
    struct pcap_pkthdr packet_header;
    int snapshot_length = BUFSIZ; // capture size in bytes
    int timeout_limit = 10000; //timeout miliseconds

    //Find network devices - must be before the error check below
    if (pcap_findalldevs(&all_devs, error_buffer) == -1) {
        printf("Error finding devices: %s\n", error_buffer);
        return 1;
    }

    if (all_devs == NULL) {
        printf("No devices found.\n");
        return 1;
    }

    // select the first available device
    device = all_devs;
    printf("Network device found: %s\n", device->name);


    // Open the device for packet capture
    handle = pcap_open_live(
        device->name, // fixes the need for const char
        snapshot_length,
        1,
        timeout_limit,
        error_buffer
        );

    if (handle == NULL) {
        printf("Error trying to open device %s: %s\n", device->name, error_buffer);
        pcap_freealldevs(all_devs);
        return 1;
    }

        packet = pcap_next(handle, &packet_header);
        if (packet == NULL) {
                printf("No packet found.\n");
                return 1;
        }

        // Print Packet details
        print_packet_info(packet, packet_header);

        // cleanup
        pcap_close(handle);
        pcap_freealldevs(all_devs);

        return 0;
}
 
/* Function to print packet info  */
void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) {
    printf("Packet captured: Length: %d bytes\n", packet_header.len);
    printf("Cap Length: %d\n", packet_header.caplen);
}
