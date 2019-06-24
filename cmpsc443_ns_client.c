////////////////////////////////////////////////////////////////////////////////
//
//  File          : cmpsc443_ns_client.c
//  Description   : This is the client side of the Needham Schroeder 
//                  protocol, and associated main processing loop.
//
//   Author        : Namita Kalady Prathap
//   Last Modified : Nov 18, 2018
//   Comments      : Implemented the code for the client side of the protocol as well.
//                   [HONORS OPTION]
//

// Includes
#include <unistd.h>
 #include <stdint.h>
#include <inttypes.h>
#include <netinet/in.h> 
#include <cmpsc311_log.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <gcrypt.h>
// Project Include Files
#include <cmpsc443_ns_proto.h>

// Defines
#define NS_ARGUMENTS "h"
#define USAGE \
	"USAGE: cmpsc443_ns_client [-h]\n" \
	"\n" \
	"where:\n" \
	"    -h - help mode (display this message)\n" \
	"\n" \
 
// socket
int sock;
 
// Functional Prototypes
int ns_client( void );

int  create_socket(void);

void ns_decrypt(unsigned char *inbuff, unsigned char *outbuff, uint16_t * size, unsigned char *iv1, ns_key_t key );

void ns_encrypt(unsigned char *inbuff, unsigned char *outbuff, uint16_t * size, unsigned char *iv1, ns_key_t key );

void swap64(char *a);

int close_socket(void);
 
int send_to_server(char *data, uint16_t *size);

int read_from_server(char *data, uint16_t *size);

////////////////////////////////////////////////////////////////////////////////
//
// Function     : main
// Description  : The main function for the Needam Schroeder protocol client
//
// Inputs       : argc - the number of command line parameters
//                argv - the parameters
// Outputs      : 0 if successful, -1 if failure

int main( int argc, char *argv[] )
{
	// Local variables
	int ch;

	// Process the command line parameters
	while ((ch = getopt(argc, argv, NS_ARGUMENTS)) != -1) {

		switch (ch) {
		case 'h': // Help, print usage
			fprintf( stderr, USAGE );
			return( -1 );

		default:  // Default (unknown)
			fprintf( stderr, "Unknown command line option (%c), aborting.\n", ch );
			return( -1 );
		}
	}

	// Create the log, run the client
    initializeLogWithFilehandle(STDERR_FILENO);
    enableLogLevels(LOG_INFO_LEVEL);
	ns_client();

	// Return successfully
	return( 0 );
}


////////////////////////////////////////////////////////////////////////////////
//
// Function     : ns_client
// Description  : The client function for the Needam Schroeder protocol server
//
// Inputs       : none
// Outputs      : 0 if successful, -1 if failure

int ns_client( void ) {

 // Method local type definition
 
 /*************************    MESSAGE 1 - TICKET REQUEST *****************************/

  // maintains status to check if socket was created successfully
  int sock_status; 
  
  tkt_req_t req; //stores request
  ns_ticket_t ticket, ticket2,ticket3,ticket4,ticket5;
   unsigned char block[NS_MAX_XMIT_SIZE];

  // creating nonce
  int retval = createNonce(&req.N1);
  logMessage(LOG_INFO_LEVEL,"Nonce  N1 is %x",req.N1);   

 //type of the message
  size_t msgtype =  htons(NS_TKT_REQ);
   
  memcpy(req.A,NS_ALICE_IDENTITY, 5);  
  memset(req.A + 5,0,11);   

  memcpy(req.B,NS_BOB_IDENTITY, 3);
  memset(req.B + 3,0,13);   

  //establishing connection
   sock_status = create_socket();   

  //if connection is  successful
  if (sock_status ==0)
  { 
 
     ticket.length = htons(40);

     memcpy(ticket.data, &ticket.length, 2);
     memcpy(ticket.data + 2,&msgtype, 2);
     memcpy(ticket.data+ 2+2,&req.N1, 8);
     memcpy(ticket.data+ 8+4,req.A, 16);
     memcpy(ticket.data+ 16+12,req.B, 16);

     logBufferMessage(LOG_INFO_LEVEL,"The buffer data for Message 1 is :", ticket.data,  40);  
     //Sending Bytes to Server
      send_to_server(ticket.data,44);

/**************************** MESSAGE 2 - TICKET RESPONSE ********************/

     
     read_from_server(ticket2.data,118);
     logBufferMessage(LOG_INFO_LEVEL,"The buffer data read from the server is :", ticket2.data,  200);
  
     uint16_t tmp, len2; 
     unsigned char temp[200], iv1[16];
     unsigned char cipher[96], tmpout[100],outBuffer[100];
     ns_key_t key; //Ka

    // to get the initilization vector
     memcpy(iv1, &ticket2.data[4], (16));  
  
     // to get the length
     memcpy(&tmp, &ticket2.data[20], (2)); 
   
     len2 = ntohs(tmp); 
   
     ns_nonce_t nonce; //To store the value from the server to check it

     // to get the encrypted data
     memcpy(cipher, ticket2.data+22, (96));  
   
     //make key from password
      makeKeyFromPassword(NS_ALICE_PASSWORD,  key);
    
   
      ns_decrypt(cipher,outBuffer , 96,iv1,key); 
      logMessage(LOG_INFO_LEVEL,"The decrypted Message 2 from Server = %s",outBuffer); 
      memcpy(&nonce, outBuffer,8);
   
      logMessage(LOG_INFO_LEVEL,"N1 from server is %x",nonce);
     
    
/******************************* MESSAGE 3 - SERVICE REQUEST ************************/
	 
        unsigned char block3[200], iv3[16], totalcipher[52], enc_N2[16],N2_temp[16];
	ns_key_t Kab;
	ns_nonce_t N2;
	 
	createNonce(&N2);
	logMessage(LOG_INFO_LEVEL, "Nonce_N2 = %d",N2); 
	logBufferMessage(LOG_INFO_LEVEL, "Nonce_N2 =",&N2, sizeof(N2)); 
	 
	memset(N2_temp, 0, 16);
	memcpy(N2_temp, &N2, 8);  
        memcpy(totalcipher, outBuffer+40, 52);
	memcpy(Kab, outBuffer+24, 16);

	logBufferMessage(LOG_INFO_LEVEL, "Kab =",Kab, sizeof(Kab)); 
	ns_encrypt(N2_temp, enc_N2, 16,iv3, Kab); 
	 
	uint16_t msg_type2 = htons(3); 
 	uint16_t ptnoncelen = htons(8);
	uint16_t paylen2 = htons( 118);

	memcpy(block3, &paylen2, 2);
	memcpy(block3+2, &msg_type2, 2);
	memcpy(block3+4, req.A, 16);
	memcpy(block3+20, req.B, 16);
	memcpy(block3+36, totalcipher, 52); 
	memcpy(block3+88, &iv3, 16);
	memcpy(block3+104, &ptnoncelen, 2);
        memcpy(block3+106, enc_N2, 16);
	logBufferMessage(LOG_INFO_LEVEL, "Service Request Message sent: ",block3, sizeof(block3));
	 
        send_to_server(block3,122);
/*****************************MESSAGE 4 - SERVICE RESPONSE ******************************/

    unsigned char rdata[250], temp_arr[44];
    unsigned char N3[8], N3t[16],N2_1[8], n3iv[16],enonce[17];
    size_t n3hdr,n3msg, n3ptl;
    ns_nonce_t N3_temp,N2_tmp, sqrn2;
 
    read_from_server(ticket4.data,38);
    logBufferMessage(LOG_INFO_LEVEL,"The ticket4.data is :", ticket4.data,  40);  
    
    memcpy(rdata,ticket4.data+22,16);

    memcpy(n3iv,ticket4.data+4,16);
    ns_decrypt(rdata,temp_arr , 128,n3iv,Kab);
    memcpy(N3, temp_arr+8,8);
          
    swap64(N3);
     
    //subtracting the nonce
     memcpy(&N3_temp,N3,8); 
     N3_temp =N3_temp-1;
     memcpy(N3,&N3_temp,8);
     swap64(N3);
     memset(N3t,0,sizeof(N3t));
     memcpy(N3t,&N3,sizeof(N3)); 
 
/*****************************MESSAGE 5 - SERVICE ACKNOWLEDGEMENT ******************************/
  
    //iv 5
    unsigned iv5[16];
    getRandomData( iv5, 16 ); 
    
    ns_encrypt(N3t,enonce , 16,iv5,Kab); 
        
    logBufferMessage(LOG_INFO_LEVEL,"The Encrypted Nonce for Message 5 :", enonce,  16);  
    
    uint16_t len_srv_req = htons(34);
    uint16_t ptlen5 = htons(8);
     
    msgtype =htons(NS_SVC_ACK);
    memcpy(ticket5.data, &len_srv_req,2);
    memcpy(ticket5.data+2, &msgtype,2); 
    memcpy(ticket5.data+4, iv5,16);
    memcpy(ticket5.data+20, &ptlen5,2);
    memcpy(ticket5.data+22, enonce,16);
     
    send_to_server(ticket5.data,38);
    logBufferMessage(LOG_INFO_LEVEL,"The buffer sent for Message 5 :", ticket5.data,  200);   
  	
 /*****************************MESSAGE 6 - DATA REQUEST ******************************/
      unsigned char datablock[200], enc_data[130], dec_data[130], iv7[16]; 

       
      read_from_server(datablock,150);
      memcpy(enc_data,datablock+22,128);
      memcpy(iv7, datablock+4, 16);
	

      ns_decrypt(enc_data,dec_data , 128,iv7,Kab);
      logBufferMessage(LOG_INFO_LEVEL, "Decrypted data block [MSG 6] is ",dec_data, sizeof(dec_data));


 /*****************************MESSAGE 7 - DATA RESPONSE ******************************/
 
     unsigned char xor_data[300], enc_xor_data[300], xordatablk[300];
     uint16_t msgtype7, len7, ptlen7;
     uint8_t xor= 182;

     for(int l = 0; l< 128;l++)
    {
         xor_data[l] = dec_data[l] ^ xor;
    }

     ns_encrypt(xor_data, enc_xor_data, 128,iv1, Kab);

     msgtype7 = htons(7);
     len7 = htons(146);
     ptlen7 = htons(128);
 
     memcpy(xordatablk,&len7,2);
     memcpy(xordatablk+2, &msgtype7,2);
     memcpy(xordatablk+4, iv1,16);
     memcpy(xordatablk+20, &ptlen7,2);
     memcpy(xordatablk+22,enc_xor_data,128);
   
     send_to_server(xordatablk,150);	 
     logBufferMessage(LOG_INFO_LEVEL, "XOR'd data block [MSG 7] is :",xordatablk, sizeof(xordatablk));


 /*****************************MESSAGE 8 - SERVICE FINISH ******************************/

     unsigned char blk8[4];
	 
     read_from_server(blk8,4);
     logBufferMessage(LOG_INFO_LEVEL, "Final Data Block is %s ",blk8, 4); 

 
}
else
 {
    //socket connection was unsuccessful.
    logMessage(LOG_INFO_LEVEL, "Couldn't establish a connection to the server. "); 
    return(-1);
 }

   //Closing socket
   if(close_socket()== -1)
  { 
    logMessage(LOG_INFO_LEVEL, "Couldn't close the socket. "); 
    return(-1);
  }   

   // Return successfully
    return(0);
}
  

////////////////////////////////////////////////////////////////////////////////
//
// Function     : NS_DECRYPT
// Description  : The function to decrypt a message.
//
// Inputs       : variable to be decrypted, variable to store the decrypted value, size of cipher text, key and IV 
// Outputs      : none

// 
 void ns_decrypt(unsigned char *inbuff, unsigned char *outbuff, uint16_t * size, unsigned char *iv1, ns_key_t key )
{   

    gcry_cipher_hd_t handle;
    gcry_error_t rval; 
    size_t IVLen = gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES);
    size_t keyLen = gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES);

   rval= gcry_cipher_open(&handle, GCRY_CIPHER_AES128,GCRY_CIPHER_MODE_CBC, 0);
   if(rval)
      { logMessage(LOG_INFO_LEVEL,"Error after cipher open");
      }  
   
   rval=  gcry_cipher_setiv (handle, iv1, IVLen);
   if(rval)
      { logMessage(LOG_INFO_LEVEL,"Error after cipher gcry_cipher_setiv");
      }

   rval=  gcry_cipher_setkey(handle, key, keyLen);
   if(rval) 
      { logMessage(LOG_INFO_LEVEL,"Error after cipher gcry_cipher_setkey");
      }

   rval=   gcry_cipher_decrypt(handle, outbuff, size, inbuff, size);
   if(rval) 
     { logMessage(LOG_INFO_LEVEL,"Error after cipher gcry_cipher_decrypt");
     }

    gcry_cipher_close(handle);
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : ns_encrypt
// Description  : The function to encrypt a message.
//
// Inputs       : variable to be encrypted, variable to store the encrypted value, size of plain text, key and IV 
// Outputs      : none

// 

 void ns_encrypt(unsigned char *inbuff, unsigned char *outbuff, uint16_t *size, unsigned char *iv1, ns_key_t key )
{   
    gcry_cipher_hd_t handle;
    gcry_error_t rval; 

   size_t keyLen = gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES);
   size_t IVLen = gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES);
 
   rval= gcry_cipher_open(&handle, GCRY_CIPHER_AES128,GCRY_CIPHER_MODE_CBC, 0);
   if(rval) 
      { logMessage(LOG_INFO_LEVEL,"Error after cipher open");
      }  
   
   rval=  gcry_cipher_setiv (handle, iv1, IVLen);
   if(rval) 
      { logMessage(LOG_INFO_LEVEL,"Error after cipher gcry_cipher_setiv");
      } 

   rval=  gcry_cipher_setkey(handle, key,keyLen);
   if(rval)
      { logMessage(LOG_INFO_LEVEL,"Error after cipher gcry_cipher_setkey");
      }

  rval=   gcry_cipher_encrypt(handle, outbuff, size, inbuff, size);

   if(rval) 
       { logMessage(LOG_INFO_LEVEL,"Error after cipher gcry_cipher_encrypt");
       }
    gcry_cipher_close(handle);
   
}
  
// 
////////////////////////////////////////////////////////////////////////////////
//
// Function     : swap64
// Description  : Function to swap nonce, 
//                as the htonll64 and ntohll64 functions are not reversing byte order.
//
// Inputs       : variable to be swapped
// Outputs      : none

void swap64(char *a)
{
  unsigned char t;
  t = a[0]; 
  a[0] = a[7];
  a[7]=t;
  t = a[1]; 
  a[1] = a[6]; 
  a[6]=t;
  t = a[2]; 
  a[2] = a[5]; 
   a[5]=t;
  t = a[3]; 
  a[3] = a[4];
  a[4]=t;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : send_to_server
// Description  : The function to send bytes to the server
//
// Inputs       : data to be sent and size of data
// Outputs      : 0 if successful, -1 if failure

int send_to_server(char *data, uint16_t *size)
{

   if (write(sock, data, size) != size)
   { 
    logMessage(LOG_INFO_LEVEL,"Error while sending to the server.");
    return -1;
   }

   return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : read_from_server
// Description  : The function to send bytes to the server
//
// Inputs       : variable to store the  bytes read and size of data
// Outputs      : 0 if successful, -1 if failure

int read_from_server(char *data, uint16_t *size)
{
  if (read(sock, data, size) != size)
  {

   logMessage(LOG_INFO_LEVEL,"Error while reading from the server.");
   return -1;
  }
  return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : create_socket
// Description  : The function to create socket and establish connection.
//
// Inputs       : none
// Outputs      : 0 if successful, -1 if failure

int create_socket(void)
{
  
   struct sockaddr_in s;
   char *ip ="127.0.0.1"; 
   
   sock =socket(PF_INET, SOCK_STREAM,0);
   if(sock ==-1)
   {
      return -1; 
   }
    
   s.sin_family = AF_INET;
 
   s.sin_port = htons(NS_SERVER_PROTOCOL_PORT);
 
   if(inet_aton(ip, &s.sin_addr) ==0)
  {
    return -1;
  }
  
   if (connect(sock, (const struct sockaddr*)&s,sizeof(struct sockaddr)) ==-1) 
  {
    return -1;
  }

  logMessage(LOG_INFO_LEVEL,"Connection established to the server.");

  return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : close_socket
// Description  : The function to close the socket.
//
// Inputs       : none
// Outputs      : 0 if successful, -1 if failure

int close_socket(void)
{
  if (close(sock) ==-1)
 {
   return -1;
 }

 logMessage(LOG_INFO_LEVEL,"Closing Socket.");

return 0;
}

