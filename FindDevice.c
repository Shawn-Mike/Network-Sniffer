Compile with: gcc find_device.c -o finddevice -lpcap */
#include <stdio.h>
#include <pcap.h>

int main(int argc, char *argv[]) {
    char error_buffer[PCAP_ERRBUF_SIZE]; /* Size is defined in pcap.h */
    pcap_t *handle;
    pcap_if_t *all_devs, *device;
   
   if (pcap_findalldevs(&all_devs, error_buffer) == -1){
        printf("Error finding device: %s\n", error_buffer);
        return 1;
   }

    if (all_devs == NULL) {
        printf("No devices found: %s\n", error_buffer);
    }

     /* Select first device */
    device = all_devs;
    printf("Network device found: %s\n", device->name);

    /* Free device list */
    pcap_freealldevs(all_devs);
    return 0;
}

