#ifndef BYTES_H
#define BYTES_H

#include <stddef.h>

/* Assumptions:
* The input strings (hex, base64, b32) are assumed to be Big endian type
* The bytes will be stored in little endian format using `usinged char`
*/

/* 
TODO: what is '\x' in C? 
* used in strings to store hex value in single byte 
*/

/* prints buffer in hex format */
void print_buf(const unsigned char *buf, size_t n);

/* prints buffer in ASCII format */
void print_ascii(const unsigned char *buf, size_t n);

/* converts a single hex character (4 bits) to a byte (8 bits) */
unsigned char hex_char_to_buf(const unsigned char inp);

/* converts a hex string to a byte array */
void hex_str_to_buf(unsigned char *out, int out_len, const unsigned char *inp, int inp_len);

#endif