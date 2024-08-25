#ifndef PROTOCOL_H
#define PROTOCOL_H

struct Packet {
  char length;
  char name[8];
  char *data;
};

#endif
