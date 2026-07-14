#ifndef RESOURCE_FORMAT_H
#define RESOURCE_FORMAT_H

typedef struct Res {
    int id;
    int live;
} Res;

void res_init(Res *r, int id);
void res_destroy(Res *r);
int filter_av(unsigned long code);
int parse_tree(const int *buf, int n, int depth);
int seh_load(const int *buf, int n);

#endif
