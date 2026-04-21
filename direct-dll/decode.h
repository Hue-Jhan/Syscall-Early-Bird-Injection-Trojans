#pragma once
#include <stdio.h>
#include "windows.h"

const char* base64_chars;
unsigned char* base64_decoded;
SIZE_T shellcode_size;

void xor_decrypt(unsigned char* data, int length, unsigned char key);
int is_base64(unsigned char c);
int base64_decode(const char* input, unsigned char* output);
int hex_decode(const char* hex, unsigned char* output);
void decodeFull();
