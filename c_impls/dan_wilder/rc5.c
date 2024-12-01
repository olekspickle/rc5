/*
 *  Author:                Dan Wilder
 *
 *  Instructor:            M. W. Schulte
 *  School:                University of Missouri - St. Louis (UMSL)
 *  Class: 	           CS 4780 - System Admin/Network Security   
 *  Semester:              Summer 2015
 *  
 *  Assignment:            Project 1 - RC5 Encryption Implementation
 *  Due Date:              09 Jul 2015 by 23:59 
 *	   
 *  Description: 
 *
 *      This project will implement the RC5 encryption algorithm with
 *    the following parameters: w = 32 bits (4 bytes), r = 12 rounds,
 *    b = 8 bytes for key K. 
 *
 *      The program executable is to be called  rc5. The program will take 
 *    a single command line argument of the key in hex [16 hex characters]. 
 *    The program will read the message as ASCII characters from standard 
 *    input until EOF is detected. 
 * 
 *      Each block will be 8 characters [64 bits] split into two 32-bit pieces,
 *    A and B. Note that it will be "little-endian" so that A is the lower half
 *    of the word. The final block will be extended with bytes of 0 if needed. 
 *    
 *      The output is the be printed to the screen as hexadecimal bytes.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

// RC5 works with words; let's emphasize this. Here is 32-bit word
typedef unsigned int WORD;

// Encryption Parameters 
#define w 32
#define r 12
#define b 8
#define t 24
#define c 2

// Rotation Operators
#define ROTATE_L(x,y) (((x)<<(y&(w-1))) | ((x)>>(w-(y&(w-1)))))
#define ROTATE_R(x,y) (((x)>>(y&(w-1))) | ((x)<<(w-(y&(w-1)))))

// Magic Constants
WORD P = 0xb7e15163;
WORD Q = 0x9e3779b9;

// Key & Expanded Key Table
unsigned char K[b]; 
WORD S[t];

// Prototypes
int isBigEndian();
void setHexKey(unsigned char *);
void setup(unsigned char *);
void encrypt(WORD *, WORD *);
void decrypt(WORD *, WORD *);

#define DEBUG

/****************************************************************************
 * main
 ****************************************************************************/

int main(int argc, unsigned char **argv) {
  
  char byte;
  int cnt, i, j;
  WORD plainTxt[2] = {0,0};
  WORD cipherTxt[2] = {0,0};

#ifdef DEBUG
  (isBigEndian()) ? printf("*** Big Endian ***\n") :
    printf("*** Little Endian ***\n\n");
#endif
 
// Some basic error checking
  if (argc < 2) { 
    printf("Key not supplied... Exiting!\n");
    exit(1);
  }

  if (strlen(argv[1]) > 2*b) {
    printf("Key exceeded %d hex characters... Exiting!\n", 2*b);
    exit(1);
  }
    
  setHexKey(argv[1]);

  printf("[HEX KEY] 0x: ");
  for (i=0; i < b; i++) {
    printf("%02x ", K[i]);
  }
  puts("\n");

  setup(K);
  
  cnt = i = j = 0;
  while ( (byte = getchar()) != EOF ) {
    
    ++cnt;
    
    // i in interval [0,3]; Alternate plainTxt index, j, every 4 characters
    if (i == 4) {
      i = 0;
      j = (j == 0) ? 1 : 0;
    }

    plainTxt[j] += (unsigned int)ROTATE_L(byte, i*8);

    // Encrypt after every 8 characters
    if (cnt % 8 == 0) {
      encrypt(plainTxt, cipherTxt);
      printf("[CIPHER HEX] %.8X %.8X\n", cipherTxt[0], cipherTxt[1]);
      
      #if 1  // Decryption
        decrypt(cipherTxt, plainTxt);
        printf("[PLAIN HEX ] %.8X %.8X\n\n", plainTxt[0], plainTxt[1]);
      #endif

      plainTxt[0] = 0; 
      plainTxt[1] = 0;
    }
      
    ++i;
  }

  // Encrypt any remaining characters
  if (cnt % 8 != 0) {
    encrypt(plainTxt, cipherTxt);
    printf("[CIPHER HEX] %.8X %.8X\n", cipherTxt[0], cipherTxt[1]);

    decrypt(cipherTxt, plainTxt);
    printf("[PLAIN HEX ] %.8X %.8X\n\n", plainTxt[0], plainTxt[1]);
    
  }

  printf("[cnt = %d : cnt (mod 8) =  %d ]\n", cnt, cnt%8);
  
  return 0;
}

/****************************************************************************
 * setup
 ****************************************************************************/

void setup(unsigned char *K) {

  WORD C, D, L[c]; /* L will be zeroed */
  int u = w/8;     /* u = number of bytes per word */
  int i, j, h; 
 
  // Copy secret key into L
  //for(i = b-1, L[c-1]=0; i != -1; --i)
  for(i = b-1; i != -1; --i)  
    L[i/u] = (L[i/u] << 8) + K[i];
    //L[i/u] = ROTATE_L(L[i/u], 8) + K[i];

  // Initialize Array S
  for (S[0] = P, i = 1; i < t; ++i)
    S[i] = S[i-1] + Q;

  // Mix in Secret Key
  for (i=j=h=C=D=0; h < 3*t; ++h, i=(i+1)%t, j=(j+1)%c) {
    C = S[i] = ROTATE_L(S[i] + (C + D), 3);
    D = L[j] = ROTATE_L(L[j] + (C + D), (C+D));
  } 
}

/****************************************************************************
 * encrypt
 ****************************************************************************/

void encrypt(WORD *plainTxt, WORD *cipherTxt) {
 
  WORD A = plainTxt[0] + S[0];
  WORD B = plainTxt[1] + S[1];

  int i;
  for (i = 1; i <= r; i++) {
    A = ROTATE_L(A^B, B) + S[2*i];
    B = ROTATE_L(B^A, A) + S[2*i+1];
  }

  cipherTxt[0] = A;
  cipherTxt[1] = B;
}

/****************************************************************************
 * decrypt
 ****************************************************************************/
/*
 *   Not a project requirement. Implemented for testing and self inquiry.
 */

void decrypt(WORD *cipherTxt, WORD *plainTxt) {
 
  WORD B = cipherTxt[1];
  WORD A = cipherTxt[0];
  
  int i;
  for (i = r; i > 0; --i) {
    B = ROTATE_R(B-S[2*i+1], A)^A;
    A = ROTATE_R(A-S[2*i], B)^B;
  } 

  plainTxt[1] = B - S[1]; 
  plainTxt[0] = A - S[0];
}

/****************************************************************************
 * setHexKey
 ****************************************************************************/
/*
 *  IMPORTANT: Make sure that parameter source len is <= 2*b. 
 */

void setHexKey(unsigned char *source) {
  
    unsigned char target[2*b];
    char *p = target;
    int i, j, offset;
 
    offset = 2*b - strlen(source);

    for ( i = 0; i < 2*b; ++i)
      target[i] = '0'; 
 
    for ( i = j = 0; i + offset < 2*b; ++i, ++j)
      target[i + offset] = source[j];

    for(i = 0; i < b; ++i) {
        sscanf(p, "%2hhx", &K[i]);
        p += 2 * sizeof(unsigned char);
    }
}

/****************************************************************************
 * isBigEndian
 ****************************************************************************/

int isBigEndian() {
  if ( htonl(47) == 47 ) {
    return 1;
  } else {
    return 0;
  }
}

