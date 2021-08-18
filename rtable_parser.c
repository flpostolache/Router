#include "skel.h"

int cmpfunc(const void *a, const void *b){
    u_int32_t prim = ((struct route_table_entry *)a)->prefix;
    u_int32_t doi = ((struct route_table_entry *)b)->prefix;
    return ( prim - doi );
}

int read_rtable(char* denumire, struct route_table_entry** rtable){

    char linie[100];
    unsigned int dim_tabel = 0;
    FILE *fisier;
    fisier = fopen(denumire,"r");
    while(fgets(linie,100,fisier)){
        u_int32_t ip_prefix = 0;
        u_int32_t ip_next_hop = 0;
        u_int32_t masca = 0;
        u_int8_t interface_num = 0;
        struct in_addr *ajutor = malloc(sizeof(struct in_addr));

        char *aux = strtok(linie, " ");
        inet_aton(aux,ajutor);
        ip_prefix = ajutor->s_addr;

        aux = strtok(NULL, " ");
        inet_aton(aux, ajutor);
        ip_next_hop = ajutor->s_addr;

        aux = strtok(NULL, " ");
        inet_aton(aux, ajutor);
        masca = ajutor->s_addr;

        aux = strtok(NULL, " ");
        interface_num = atoi(aux);

        dim_tabel++;
        *rtable = realloc(*rtable,dim_tabel * sizeof(struct route_table_entry));
        (*rtable)[dim_tabel-1].prefix = ntohl(ip_prefix);
        (*rtable)[dim_tabel-1].next_hop = ntohl(ip_next_hop);
        (*rtable)[dim_tabel-1].mask = ntohl(masca);
        (*rtable)[dim_tabel-1].interface = interface_num;
    }
    fclose(fisier);
    qsort(*rtable, dim_tabel, sizeof(struct route_table_entry),cmpfunc);
    return dim_tabel;
}