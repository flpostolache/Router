#include <queue.h>
#include "skel.h"

struct route_table_entry *tabel;
int size_tabel;

struct arp_entry *arp_table;
int arp_table_len;

int i;

struct route_table_entry *get_best_route(__u32 dest_ip);
int get_best_arp_route(u_int32_t ip);
int cmpfunc2(const void *a, const void *b);

unsigned char broadcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

int main(int argc, char *argv[])
{
	packet m;
	int rc;
	size_tabel = read_rtable(argv[1], &tabel);
	queue q;
	q = queue_create();

	init(argc - 2, argv + 2);

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");

		struct ethhdr *eth_hdr = (struct ethhdr*)m.payload;
		if(ntohs(eth_hdr->h_proto) == ETH_P_ARP){

			struct arp_header *arp_hdr = parse_arp(m.payload);

			if( ntohs(arp_hdr->op) == ARPOP_REQUEST && arp_hdr->tpa == get_interface_ip(m.interface)){
				struct ethhdr *cerere = malloc(sizeof(struct ethhdr));
				unsigned char dest[6]; 
				get_interface_mac(m.interface, dest);
				build_ethhdr( (struct ether_header *)cerere, dest, arp_hdr->sha, htons(ETH_P_ARP) );
				send_arp(arp_hdr->spa,arp_hdr->tpa,(struct ether_header *)cerere,m.interface, htons(ARPOP_REPLY));
				continue;
			}
			if(ntohs(arp_hdr->op) == ARPOP_REPLY && arp_hdr->tpa == get_interface_ip(m.interface)){
				arp_table_len++;
				arp_table = (struct arp_entry *)realloc(arp_table,arp_table_len*sizeof(struct arp_entry));
				arp_table[arp_table_len - 1].ip = ntohl(arp_hdr->spa);
				memcpy(arp_table[arp_table_len - 1].mac,arp_hdr->sha,6);
				
				while(!queue_empty(q)){
					packet *p = (packet *)malloc(sizeof(packet));
					p = (packet *)queue_deq(q);
					struct ethhdr *eth_hdr_pachet = (struct ethhdr*)p->payload;
					struct iphdr *ip_hdr_pachet = (struct iphdr*) (p->payload + sizeof(struct ethhdr));
					struct route_table_entry  *entry_bun = get_best_route(ntohl(ip_hdr_pachet->daddr));
					int poz_gas = get_best_arp_route(entry_bun->next_hop);
					if(poz_gas == -1000)
						break;
					else{
						memcpy(eth_hdr_pachet->h_dest,arp_table[poz_gas].mac,6);
						get_interface_mac(entry_bun->interface,eth_hdr_pachet->h_source);
						send_packet(entry_bun->interface,p);
					}
				}
				continue;
			}
			continue;
		}
		if(ntohs(eth_hdr->h_proto) == ETH_P_IP){
			struct iphdr *ip_hdr = (struct iphdr*)(m.payload + sizeof(struct ethhdr));
			
			if(ip_hdr->daddr == get_interface_ip(m.interface)){
				if(ip_hdr->protocol == 1){
					struct icmphdr *icmp_hdr = parse_icmp(m.payload);
					if(icmp_hdr->type == 8){
						send_icmp(ip_hdr->saddr,ip_hdr->daddr,eth_hdr->h_dest,eth_hdr->h_source,0, 0,m.interface,icmp_hdr->un.echo.id,icmp_hdr->un.echo.sequence);
						continue;
					}
				}
				continue;
			}else{
				if(ip_hdr->ttl <= 1){
					send_icmp_error(ip_hdr->saddr,ip_hdr->daddr,eth_hdr->h_dest,eth_hdr->h_source,11, 0,m.interface);
					continue;
				}
				if( ip_checksum(ip_hdr,sizeof(struct iphdr))){
					continue;
				}
				ip_hdr->ttl--;
				ip_hdr->check = 0;
				ip_hdr->check = ip_checksum(ip_hdr,sizeof(struct iphdr));

				struct route_table_entry  *entry = get_best_route(ntohl(ip_hdr->daddr));
				if(entry == NULL){
					send_icmp_error(ip_hdr->saddr,ip_hdr->daddr,eth_hdr->h_dest,eth_hdr->h_source,3, 0,m.interface);
					continue;
				}
				int poz_gasit = get_best_arp_route(entry->next_hop);
				if(poz_gasit == -1000){
					struct ethhdr *vreau_mac = malloc(sizeof(struct ethhdr));
					unsigned char source[6];
					get_interface_mac(entry->interface, source);
					build_ethhdr( (struct ether_header *)vreau_mac, source, broadcast, htons(ETH_P_ARP) );
					send_arp( htonl(entry->next_hop), get_interface_ip(entry->interface),(struct ether_header *)vreau_mac,entry->interface,htons(ARPOP_REQUEST));
					packet *de_bagat_in_queue = (packet *)malloc(sizeof(packet));
					memcpy(de_bagat_in_queue,&m,sizeof(packet));
					queue_enq(q,de_bagat_in_queue);
					continue;

				}else{
					memcpy(eth_hdr->h_dest,arp_table[poz_gasit].mac,sizeof(arp_table[poz_gasit].mac));
					get_interface_mac(entry->interface,eth_hdr->h_source);
					send_packet(entry->interface, &m);
					continue;
				}
			}
		}
	}
}

struct route_table_entry *get_best_route(__u32 dest_ip) {
	struct route_table_entry *n = NULL;
	for(i=0; i< size_tabel; i++)
		if((tabel[i].mask & dest_ip) == tabel[i].prefix)
				if(n == NULL || tabel[i].mask > n->mask)
					n = &tabel[i];
	return n;
}
int get_best_arp_route(u_int32_t ip){
	int poz_gasit = -1000;
	for(int i = 0; i < arp_table_len; i++){
		if(ip == arp_table[i].ip)
			poz_gasit = i;
	}
	return poz_gasit;
}
