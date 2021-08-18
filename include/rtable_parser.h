#include <stdio.h>
#include <stdlib.h>

struct route_table_entry {
	u_int32_t prefix;
	u_int32_t next_hop;
	u_int32_t mask;
	unsigned int interface;
};

int read_rtable(char *fisier_de_citit, struct route_table_entry** rtable);