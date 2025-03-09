/* Compile with: gcc DeviceInfo.C -o DeviceInfo -lpcap */
/* See Docs: https://github.com/the-tcpdump-group/libpcap/blob/master/pcap/pcap.h && https://pubs.opengroup.org/onlinepubs/7908799/xns/arpainet.h.html */

#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>

#define IP_BUFFER_SIZE 16
#define SUBNET_BUFFER_SIZE 16

int main(int argc, char *argv[]) {
    char ip[IP_BUFFER_SIZE];
    char subnet_mask[SUBNET_BUFFER_SIZE];
    bpf_u_int32 ip_raw; /* IP as an int */
    bpf_u_int32 subnet_mask_raw; /* Subnet mask as an int */
    int lookup_return_id;
    char error_buffer[PCAP_ERRBUF_SIZE]; /* Error message buffer */
    pcap_if_t *all_devs, *device;
    struct in_addr address; /* Used for both IP and subnet */

    /* Find network devices */
    if (pcap_findalldevs(&all_devs, error_buffer) == -1) {
        printf("Error finding device: %s\n", error_buffer);
        return 1;
    }

    /* No device found */
    if (all_devs == NULL) {
        printf("No devices found.\n");
        return 1;
    }

    /* Select the first available device */
    device = all_devs;
    printf("Network device found: %s\n", device->name);

    /* Get IP and subnet mask of the device */
    lookup_return_id = pcap_lookupnet(
        device->name,  // FIX: Pass device name (char *)
        &ip_raw,
        &subnet_mask_raw,
        error_buffer
    );

    /* Handle errors from pcap_lookupnet */
    if (lookup_return_id == -1) {
        printf("Error retrieving IP information: %s\n", error_buffer);
        pcap_freealldevs(all_devs);
        return 1;
    }

    /* Convert IP to human-readable form */
    address.s_addr = ip_raw;
    const char *ip_str = inet_ntoa(address);
    strncpy(ip, ip_str, IP_BUFFER_SIZE - 1);
    ip[IP_BUFFER_SIZE - 1] = '\0'; // Ensure null termination

    /* Convert subnet mask to human-readable form */
    address.s_addr = subnet_mask_raw;
    const char *subnet_str = inet_ntoa(address);
    strncpy(subnet_mask, subnet_str, SUBNET_BUFFER_SIZE - 1);
    subnet_mask[SUBNET_BUFFER_SIZE - 1] = '\0';

    /* Print results */
    printf("IP Address: %s\n", ip);
    printf("Subnet Mask: %s\n", subnet_mask);

    /* Free the device list */
    pcap_freealldevs(all_devs);

    return 0;
}
