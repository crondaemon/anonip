
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <time.h>
#include <getopt.h>

#define BETWEEN(n, l, u) ((n) >= (l) && (n) <= (u)) 

uint32_t get_natural_mask(uint32_t ip)
{
  uint32_t iph = ntohl(ip);
  uint8_t msb = iph >> 24;
  
  if (BETWEEN(msb, 1, 127)) {
    return htonl(0xFF000000);
  }
  
  if (BETWEEN(msb, 128, 191)) {
    return htonl(0xFFFF0000);
  }
  
  if (BETWEEN(msb, 192, 223)) {
    return htonl(0xFFFFFF00);
  }
  
  return 0xFFFFFFFF;
}

uint32_t anonip(uint32_t ip, uint32_t* netmask, uint32_t* key)
{
  uint32_t wildmask;
  uint32_t network;
  uint32_t ipbase;
  uint32_t newip;

  if (*netmask == 0) {
    *netmask = get_natural_mask(ip);
  }

  if (*key == 0) {
    srandom(time(NULL));
    *key = random();
  }
    
  wildmask = ~ntohl(*netmask);
  network = ntohl(ip) & ntohl(*netmask);
  
  ipbase = ntohl(ip) & wildmask;
  newip = (ipbase + *key) % wildmask;
  
  return htonl(network + newip);
}

void usage(char* argv0)
{
  fprintf(stderr, "\nUsage: %s <ip> [-m <netmask>] [-k <key>] [-v]\n\n", argv0);
  fprintf(stderr, "-m: specify a netmask if not natural\n");
  fprintf(stderr, "-k: anonymization key\n");
  fprintf(stderr, "-v: verbose mode\n");
} 

int main(int argc, char* argv[])
{
  uint32_t ip;
  uint32_t mask = 0;
  uint32_t key = 0;
  uint32_t ip2;
  char ipbuf[INET_ADDRSTRLEN];
  char maskbuf[INET_ADDRSTRLEN];
  char ip2buf[INET_ADDRSTRLEN];
  int opt;
  bool verbose = false;

  if (argc == 1) {
    usage(argv[0]);
    return 1;
  }

  while ((opt = getopt(argc, argv, "m:k:v")) != -1) {
    switch (opt) {
      case 'm':
        mask = inet_addr(optarg);
        break;
      case 'k':
        key = strtoul(optarg, NULL, 10);
        break;
      case 'v':
        verbose = true;
        break;
      default:
        fprintf(stderr, "Invalid option: %c\n", opt);
        break;
    }
  }
  
  if (!argv[optind]) {
    usage(argv[0]);
    return 1;
  }
                                                                      
  ip = inet_addr(argv[optind]);
  
  ip2 = anonip(ip, &mask, &key);
  if (verbose) {
    fprintf(stderr, "Using ip: %s\n", inet_ntop(AF_INET, &ip, ipbuf, INET_ADDRSTRLEN));
    fprintf(stderr, "Using netmask: %s\n", inet_ntop(AF_INET, &mask, maskbuf, INET_ADDRSTRLEN));
    fprintf(stderr, "Using key: 0x%.4X (%u)\n", key, key);
  }
   
  printf("%s\n", inet_ntop(AF_INET, &ip2, ip2buf, INET_ADDRSTRLEN));
  return 0;
}