
#include <stdint.h>  // included for  uint8_t ..etc 
#include <stdbool.h> // included for  bool
#include <stddef.h> // included for NULL definition
#include <string.h> // included for memset/memcpy definition
#include <stdio.h> // included for printf definition
#include <stdlib.h> // exit function
#include <assert.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>

#define DOIP_HEADER_LEN			8 // bytes
#define DOIP_LISTENING_PORT     13400
#define DOIP_ENTITY_IPADDRESS	"198.18.36.96"
#define DOIP_ENTITY_SA			0x0E80
#define DOIP_ENTITY_TA			0x1005
#define DOIP_UPLOAD_DOWNLOAD_LENGTH 	3000	// bytes

#define ISOUDS_SA_SEEDLEN_LEVEL05   0x03U
#define ISOUDS_SA_KEYLEN_LEVEL05    0x04U 

#define ISOUDS_SA_SEEDLEN_LEVEL29   0x03U
#define ISOUDS_SA_KEYLEN_LEVEL29    0x04U 

#define     ISOUDS_DS              (0x01U)      /* Default Session */
#define     ISOUDS_PRGS            (0x02U)      /* Programming Session */
#define     ISOUDS_EXTDS           (0x03U)      /* Extended diagnostic Session */

#define ISOUDS_INSTALL_PROGRESS_ID_F1BA             (uint16_t)(0xF1BA)
#define  ISOUDS_RTNID_CHECK_PRE_CONDITIONS             ((uint16_t)0x0202)
#define  ISOUDS_RTNID_MD5_CHECK                        ((uint16_t)0x0210)
#define  ISOUDS_RTNID_CHECK_PRG_INTEGRITY              ((uint16_t)0x0211)
#define  ISOUDS_RTNID_PACK_SIGN_VERIFICAT              ((uint16_t)0x0212)
#define  ISOUDS_RTNID_START_INSTALLATION               ((uint16_t)0x0208)

static uint8_t downloadData[DOIP_UPLOAD_DOWNLOAD_LENGTH];
static uint8_t uploadData[DOIP_UPLOAD_DOWNLOAD_LENGTH];

static int tcpSockFd;

static int32_t blockLength = 0; 

static uint32_t seed_to_key(uint32_t seed) {
    uint32_t key = 0;
	size_t i = 0;
    if (seed != 0) {
        for (i = 0; i < 35; i++) {
            if (seed & 0x80000000) {
                seed = seed << 1;
                seed = seed ^ 0x41204653;
            } else {
                seed = seed << 1;
            }
        }
        key = seed;
    }
    return key;
}

static void ISOUDS_SACalKey(uint8_t *pSeedBuf, uint8_t *pKeyBuf)
{
	uint32_t num;
    num = (((uint32_t)pSeedBuf[0]) << 16) | (((uint32_t)pSeedBuf[1]) << 8) | (((uint32_t)pSeedBuf[2]) << 0) ;
    num = seed_to_key(num);
    pKeyBuf[0] = (num >> 24) & 0xFFU;
    pKeyBuf[1] = (num >> 16) & 0xFFU;
    pKeyBuf[2] = (num >>  8) & 0xFFU;
    pKeyBuf[3] = (num >>  0) & 0xFFU;
#if 0	
	uint32_t num;

	num =  (((uint32_t)pSeedBuf[0]) << 16) | (((uint32_t)pSeedBuf[1]) << 8) | (((uint32_t)pSeedBuf[2]) << 0) ;

	// Calculate 1's complement
	num = ~num;

	pKeyBuf[0] = (num >>  16) & 0xFFU;
	pKeyBuf[1] = (num >>   8) & 0xFFU;
	pKeyBuf[2] = (num >>   0) & 0xFFU;
#endif
	return;
}

static void ISOUDS_SACalKey19(uint8_t *pSeedBuf, uint8_t *pKeyBuf)
{    
	printf("seed: 0x%02x 0x%02x 0x%02x\n", pSeedBuf[0], pSeedBuf[1], pSeedBuf[2]);
	uint32_t num;
    num = (((uint32_t)pSeedBuf[0]) << 16) | (((uint32_t)pSeedBuf[1]) << 8) | (((uint32_t)pSeedBuf[2]) << 0) ;
    num = seed_to_key(num);
    pKeyBuf[0] = (num >> 24) & 0xFFU;
    pKeyBuf[1] = (num >> 16) & 0xFFU;
    pKeyBuf[2] = (num >>  8) & 0xFFU;
    pKeyBuf[3] = (num >>  0) & 0xFFU;
#if 0	
	uint32_t num;

	num =  (((uint32_t)pSeedBuf[0]) << 16) | (((uint32_t)pSeedBuf[1]) << 8) | (((uint32_t)pSeedBuf[2]) << 0) ;

	// Calculate 2's complement
	num = ~num + 1;

	pKeyBuf[0] = (num >>  16) & 0xFFU;
	pKeyBuf[1] = (num >>   8) & 0xFFU;
	pKeyBuf[2] = (num >>   0) & 0xFFU;
#endif
	return;
}

static void sendSA(void)
{
	uint8_t txBuffer[20];
	uint8_t readBuf[512];
	uint8_t packetBuf[512];
	int length = 0;
	int packetNumber = 0;
	int error;
	int rxBytes;
	uint8_t pass = 0;
	uint8_t key[ISOUDS_SA_KEYLEN_LEVEL29];
		
	txBuffer[0] = 0x02;
	txBuffer[1] = ~0x02;
	txBuffer[2] = 0x80;
	txBuffer[3] = 0x01; // Diag message
	txBuffer[4] = 0;	
	txBuffer[5] = 0;
	txBuffer[6] = 0;
	txBuffer[7] = 6;   // 6 bytes length
	
	txBuffer[8] = (DOIP_ENTITY_SA >> 8) & 0xff;
	txBuffer[9] = (DOIP_ENTITY_SA >> 0) & 0xff;
	txBuffer[10] = (DOIP_ENTITY_TA >> 8) & 0xff;
	txBuffer[11] = (DOIP_ENTITY_TA >> 0) & 0xff;
    
	txBuffer[12] = 0x27;	// Security Access
	txBuffer[13] = 0x29;	// Request seed
	
	error = send(tcpSockFd, &txBuffer[0], DOIP_HEADER_LEN+6, 0);
	
	if (error  < 0)
    {		
		printf("TCP connection sending SA request seed failed... closing. error = %d\n", error);
		close (tcpSockFd);
		exit(EXIT_FAILURE);
	}
	printf("sent reqSeed len = %d\n", error);
readAgain:	
	if ((rxBytes = read(tcpSockFd, &readBuf[0], sizeof(readBuf))) <= 0)
	{		
		printf("TCP connection closed  or error = %d\n", rxBytes);
		close (tcpSockFd);
		exit(EXIT_FAILURE);
	}
	else
    {
		printf("Received reqSeed ack/respone = %u\n", rxBytes);		
		uint8_t i;
		for(i=0; i < rxBytes; i++)
		{
			printf("0x%02x ", readBuf[i]);
		}
		printf("\n");
		// DOIP ACK response 13 bytes 
		// reqSeed response 17 bytes
		if (rxBytes == 13) 
		{
			pass++;
		}
		else if (rxBytes > 13)
		{
			while (rxBytes > 0)
			{
				packetNumber++;
				printf("packet %d: ", packetNumber);
				for (i=0; i< 4; i++)
				{
					length +=readBuf[4 + i] << (4*(3-i)); // 4 :payload length form bit 4. has 4 bytes.
				}
				printf("payloadlength %d: \n", length);
				if (length == 0 ) 
				{
					length = 5; // if packet have no payload it is 13 bytes.
				}
				for (i=0; i<(length+DOIP_HEADER_LEN); i++) // 8 : DoIP header is 8 bytes
				{
					packetBuf[i] = readBuf[i];
					printf("0x%02x ", packetBuf[i]);
				}
				printf("\n");
				rxBytes -= (length+DOIP_HEADER_LEN);
				for (i=0; i<rxBytes; i++)
				{
					readBuf[i] = readBuf[length+DOIP_HEADER_LEN+i];
				}
				length = 0;
			}
			pass = 2;
		}
		else
		{
			printf("sendSA: unexpected response received.\n");
			close (tcpSockFd);
			exit(EXIT_FAILURE);
		}		
		
		if (pass < 2)
	    {
			goto readAgain;
		}
	}
	
	ISOUDS_SACalKey(&readBuf[14], &key[0]);
	
	txBuffer[0] = 0x02;
	txBuffer[1] = ~0x02;
	txBuffer[2] = 0x80;
	txBuffer[3] = 0x01; // Diag message
	txBuffer[4] = 0;	
	txBuffer[5] = 0;
	txBuffer[6] = 0;
	txBuffer[7] = 0x0A;   // 9 bytes length
	
	txBuffer[8] = (DOIP_ENTITY_SA >> 8) & 0xff;
	txBuffer[9] = (DOIP_ENTITY_SA >> 0) & 0xff;
	txBuffer[10] = (DOIP_ENTITY_TA >> 8) & 0xff;
	txBuffer[11] = (DOIP_ENTITY_TA >> 0) & 0xff;
    
	txBuffer[12] = 0x27;	// Security Access
	txBuffer[13] = 0x2A;	// Send key
	
	txBuffer[14] = key[0];
	txBuffer[15] = key[1];
	txBuffer[16] = key[2];
	txBuffer[17] = key[3];
	
	pass = 0;
	error = send(tcpSockFd, &txBuffer[0], DOIP_HEADER_LEN+10, 0);
	
	if (error  < 0)
    {		
		printf("TCP connection sending SA request seed failed... closing. error = %d\n", error);
		close (tcpSockFd);
		exit(EXIT_FAILURE);
	}
	
	printf("sent key len = %d\n", error);

readAgain2:	
	if ((rxBytes = read(tcpSockFd, &readBuf[0], sizeof(readBuf))) <= 0)
	{		
		printf("TCP connection close error = %d\n", rxBytes);
		close (tcpSockFd);
		exit(EXIT_FAILURE);
	}
	else
    {
		printf("Received sendKey ack/respone = %u\n", rxBytes);		
		uint8_t i;
		for(i=0; i < rxBytes; i++)
		{
			printf("0x%02x ", readBuf[i]);
		}
		printf("\n");
		
		// DOIP ACK response 13 bytes 
		// sendKey response 14 bytes
        packetNumber = 0;
		if (rxBytes == 13) 
		{
			pass++;
		}
		else if (rxBytes > 13)
		{
			while (rxBytes > 0)
			{
				packetNumber++;
				printf("packet %d: ", packetNumber);
				for (i=0; i< 4; i++)
				{
					length +=readBuf[4 + i] << (4*(3-i)); // 4 :payload length form bit 4. has 4 bytes.
				}
				printf("payloadlength %d: \n", length);
				if (length == 0 ) 
				{
					length = 5; // if packet have no payload it is 13 bytes.
				}
				for (i=0; i<(length+DOIP_HEADER_LEN); i++) // 8 : DoIP header is 8 bytes
				{
					packetBuf[i] = readBuf[i];
					printf("0x%02x ", packetBuf[i]);
				}
				printf("\n");
				rxBytes -= (length+DOIP_HEADER_LEN);
				for (i=0; i<rxBytes; i++)
				{
					readBuf[i] = readBuf[length+DOIP_HEADER_LEN+i];
				}
				length = 0;
			}
			pass = 2;
		}
		else
		{
			printf("sendSA: unexpected response received.\n");
			close (tcpSockFd);
			exit(EXIT_FAILURE);
		}		
		
		if (pass < 2)
	    {
			goto readAgain2;
		}
	}	
}

static void sendReadByID(uint16_t readbyID)
{
	uint8_t txBuffer[DOIP_HEADER_LEN + 7];
	uint8_t readBuf[512];
	int error;
	uint8_t pass = 0;
	int rxBytes;
	uint8_t i;
	
	txBuffer[0] = 0x02;
	txBuffer[1] = ~0x02;
	txBuffer[2] = 0x80;
	txBuffer[3] = 0x01; // Diag message
	txBuffer[4] = 0;	
	txBuffer[5] = 0;
	txBuffer[6] = 0;
	txBuffer[7] = 7;   // bytes
	
	txBuffer[8] = (DOIP_ENTITY_SA >> 8) & 0xff;
	txBuffer[9] = (DOIP_ENTITY_SA >> 0) & 0xff;
	txBuffer[10] = (DOIP_ENTITY_TA >> 8) & 0xff;
	txBuffer[11] = (DOIP_ENTITY_TA >> 0) & 0xff;
    
	txBuffer[12] = 0x22;	// SID for read by ID
	
	txBuffer[13] = (readbyID >> 8) & 0xFFU;	// mandatory ID bytes
	txBuffer[14] = readbyID & 0XFFU;	 // mandatory Id bytes
	
	error = send(tcpSockFd, &txBuffer[0], DOIP_HEADER_LEN+7, 0);
	
	if (error  < 0)
    {		
		printf("TCP connection sending extend session request failed... closing. error = %d\n", error);
		close (tcpSockFd);
		exit(EXIT_FAILURE);
	}

	printf("sent read by ID request len = %d\n", error);
	
	printf("======================================\n");
	printf("Source Logical address: 0x");
	for (i=0; i< 2; i++)
	{
		printf("%02x", txBuffer[8 + i]);
	}				
	printf("\n");
	
	printf("Destination Logical address: 0x");
	for (i=0; i< 2; i++)
	{
		printf("%02x", txBuffer[10 + i]);
	}
	printf("\n");
									
	printf("UDS service respose ID: 0x%02x\n", txBuffer[12]);
	
	printf("ReadByID Data Identifier: 0x");
	for (i=0; i< 2; i++)
	{
		printf("%02x", txBuffer[13 + i]);
	}
	printf("\n");
	
	printf("======================================\n");
	
readAgain:
	if ((rxBytes = read(tcpSockFd, &readBuf[0], sizeof(readBuf))) <= 0)
	{		
		printf("TCP connection closed  or error = %d\n", rxBytes);
		close (tcpSockFd);
		exit(EXIT_FAILURE);
	}
	else
    {
		printf("Received read by ID ack/respone = %u\n", rxBytes);		
		for(i=0; i < rxBytes; i++)
		{
			printf("0x%02x ", readBuf[i]);
		}
		printf("\n");
		// DOIP ACK response 13 bytes 
		// Read data by ID response 19 bytes
		if ((rxBytes == 13) || (rxBytes == 19)) 
		{
			pass++;
		}
		else if ((rxBytes == 23) || (rxBytes >= 62)) // Two reponses came together.. Todo: Handle this in betterway
		{
			pass = 2;
		}
		else
		{
			printf("sendReadByID: unexpected response received.\n");
			close (tcpSockFd);
			exit(EXIT_FAILURE);
		}

		if ((rxBytes ==  19) || (rxBytes == 32) )
		{

            uint8_t offset;

            offset = (rxBytes ==  32) ? 13: 0;
        
			printf("Response for UDS ReadByID request: \n");
			printf("======================================\n");
			printf("Source Logical address: 0x");
			for (i=0; i< 2; i++)
			{
				printf("%02x", readBuf[offset + 8 + i]);
			}				
			printf("\n");
			
			printf("Destination Logical address: 0x");
			for (i=0; i< 2; i++)
			{
				printf("%02x", readBuf[offset + 10 + i]);
			}
			printf("\n");
											
			printf("UDS service respose ID: 0x%02x\n", readBuf[12]);
			
			printf("ReadByID Data Identifier: 0x");
			for (i=0; i< 2; i++)
			{
				printf("%02x", readBuf[offset + 13 + i]);
			}
			printf("\n");
			
			printf("ReadByID Response: ");
			for (i=0; i< 4; i++)
			{
				printf("0x%02x ", readBuf[offset + 15 + i]);
			}
			printf("\n");
			printf("======================================\n");
		}
		if (pass < 2)
	    {
			goto readAgain;
		}
	}
}

static void sendWriteByID(uint16_t writeID)
{
	uint8_t txBuffer[512];
	uint8_t readBuf[512];
	int error;
	uint8_t pass = 0;
	int rxBytes;
	uint8_t i;
	
	txBuffer[0] = 0x02;
	txBuffer[1] = ~0x02;
	txBuffer[2] = 0x80;
	txBuffer[3] = 0x01; // Diag message
	txBuffer[4] = 0;	
	txBuffer[5] = 0;
	txBuffer[6] = 0;
	txBuffer[7] = 55;   // bytes
	
	txBuffer[8] = (DOIP_ENTITY_SA >> 8) & 0xff;
	txBuffer[9] = (DOIP_ENTITY_SA >> 0) & 0xff;
	txBuffer[10] = (DOIP_ENTITY_TA >> 8) & 0xff;
	txBuffer[11] = (DOIP_ENTITY_TA >> 0) & 0xff;
    
	txBuffer[12] = 0x2E;	// SID for write by ID
	
	txBuffer[13] = (writeID >> 8) & 0xFFU;	// mandatory ID bytes
	txBuffer[14] = writeID & 0xFFU;	// mandatory Id bytes

	txBuffer[15] = 0x21;	// year
	txBuffer[16] = 0x03;	// month
	txBuffer[17] = 0x17;	// day
	txBuffer[18] = 0x10;	// hour
	txBuffer[19] = 0x00;	// minute
	txBuffer[20] = 0x00;	// seconds

	// 30 bytes fingerprint write - 0xFF - VIN
	for (i=0;  i<30; i++)
	{
		txBuffer[21+i] = 0xFF;
	}
	
	error = send(tcpSockFd, &txBuffer[0], DOIP_HEADER_LEN+7+48, 0);
	
	if (error  < 0)
    {		
		printf("TCP connection sending extend session request failed... closing. error = %d\n", error);
		close (tcpSockFd);
		exit(EXIT_FAILURE);
	}

	printf("sent write by ID request len = %d\n", error);
	
	printf("======================================\n");
	printf("Source Logical address: 0x");
	for (i=0; i< 2; i++)
	{
		printf("%02x", txBuffer[8 + i]);
	}				
	printf("\n");
	
	printf("Destination Logical address: 0x");
	for (i=0; i< 2; i++)
	{
		printf("%02x", txBuffer[10 + i]);
	}
	printf("\n");
									
	printf("UDS service respose ID: 0x%02x\n", txBuffer[12]);
	
	printf("Write Data Identifier: 0x");
	for (i=0; i< 2; i++)
	{
		printf("%02x", txBuffer[13 + i]);
	}
	printf("\n");
	
	printf("Write Data : 0x");
	for (i=0; i< 17; i++)
	{
		printf("%02x", txBuffer[15 + i]);
	}
	printf("\n");
	
	printf("======================================\n");
	
readAgain:
	if ((rxBytes = read(tcpSockFd, &readBuf[0], sizeof(readBuf))) <= 0)
	{		
		printf("TCP connection closed  or error = %d\n", rxBytes);
		close (tcpSockFd);
		exit(EXIT_FAILURE);
	}
	else
    {
		printf("Received read by ID ack/respone = %u\n", rxBytes);		
		for(i=0; i < rxBytes; i++)
		{
			printf("0x%02x ", readBuf[i]);
		}
		printf("\n");
		// DOIP ACK response 13 bytes 
		// write data by ID response 19 bytes
		if (rxBytes == 13) 
		{
			pass++;
		}
		else if (rxBytes == 15) {
			pass = 2;
		}
		else if (rxBytes == 28) // Two reponses came together.. Todo: Handle this in betterway
		{
			pass = 2;
		}
		else if (rxBytes == 30) // Two reponses came together.. Todo: Handle this in betterway
		{
			pass = 3;
		}
		else if (rxBytes == 43) // Three reponses came together.. Todo: Handle this in betterway
		{
			pass = 3;
		}
		else
		{
			printf("sendReadByID: unexpected response received.\n");
			close (tcpSockFd);
			exit(EXIT_FAILURE);
		}

		if ((pass == 3) && ((rxBytes ==  15) || (rxBytes == 30)))
		{

            uint8_t offset;

            offset = (rxBytes ==  30) ? 15: 0;
        
			printf("Response for UDS Write By ID request: \n");
			printf("======================================\n");
			printf("Source Logical address: 0x");
			for (i=0; i< 2; i++)
			{
				printf("%02x", readBuf[offset + 8 + i]);
			}				
			printf("\n");
			
			printf("Destination Logical address: 0x");
			for (i=0; i< 2; i++)
			{
				printf("%02x", readBuf[offset + 10 + i]);
			}
			printf("\n");
											
			printf("UDS service write ID: 0x%02x\n", readBuf[12]);
			
			printf("WriteByID Data Identifier: 0x");
			for (i=0; i< 2; i++)
			{
				printf("%02x", readBuf[offset + 13 + i]);
			}
			printf("\n");
			printf("======================================\n");
		}
		if (pass < 3)
	    {
			goto readAgain;
		}
	}
}

static void sendDiagExtendSessnion(void)
{
	uint8_t txBuffer[14];
	uint8_t readBuf[512];
	int error;
	uint8_t pass = 0;
	int rxBytes;
	
	txBuffer[0] = 0x02;
	txBuffer[1] = ~0x02;
	txBuffer[2] = 0x80;
	txBuffer[3] = 0x01; // Diag message
	txBuffer[4] = 0;	
	txBuffer[5] = 0;
	txBuffer[6] = 0;
	txBuffer[7] = 6;   // 6 bytes length
	
	txBuffer[8] = (DOIP_ENTITY_SA >> 8) & 0xff;
	txBuffer[9] = (DOIP_ENTITY_SA >> 0) & 0xff;
	txBuffer[10] = (DOIP_ENTITY_TA >> 8) & 0xff;
	txBuffer[11] = (DOIP_ENTITY_TA >> 0) & 0xff;
    
	txBuffer[12] = 0x10;	// DiaSession congtrol
	txBuffer[13] = 0x03;	// Extend the session
	
	error = send(tcpSockFd, &txBuffer[0], DOIP_HEADER_LEN+6, 0);
	
	if (error  < 0)
    {		
		printf("TCP connection sending extend session request failed... closing. error = %d\n", error);
		close (tcpSockFd);
		exit(EXIT_FAILURE);
	}

	printf("sent extend diag session request len = %d\n", error);
	
readAgain:
	if ((rxBytes = read(tcpSockFd, &readBuf[0], sizeof(readBuf))) <= 0)
	{		
		printf("TCP connection closed  or error = %d\n", rxBytes);
		close (tcpSockFd);
		exit(EXIT_FAILURE);
	}
	else
    {
		printf("Received extend diag session ack/respone = %u\n", rxBytes);		
		uint8_t i;
		for(i=0; i < rxBytes; i++)
		{
			printf("0x%02x ", readBuf[i]);
		}
		printf("\n");
		// DOIP ACK response 13 bytes 
		// extend diag session response 18 bytes
		if ((rxBytes == 13) || (rxBytes == 18)) 
		{
			pass++;
		}
		else if (rxBytes == 31) // Two reponses came together.. Todo: Handle this in betterway
		{
			pass = 2;
		}
		else
		{
			printf("sendDiagExtendSessnion: unexpected response received.\n");
			close (tcpSockFd);
			exit(EXIT_FAILURE);
		}		
		
		if (pass < 2)
	    {
			goto readAgain;
		}
	}
}

static void sendMd5check()
{
	uint8_t txBuffer[128] = {0};
	uint8_t readBuf[512];
	int error;
	uint8_t pass = 0;
	int rxBytes;
	uint8_t i;
	uint16_t id = 0x0210;
	
	txBuffer[0] = 0x02;
	txBuffer[1] = ~0x02;
	txBuffer[2] = 0x80;
	txBuffer[3] = 0x01; // Diag message
	txBuffer[4] = 0;	
	txBuffer[5] = 0;
	txBuffer[6] = 0;
	txBuffer[7] = 29;   // bytes
	
	txBuffer[8] = (DOIP_ENTITY_SA >> 8) & 0xff;
	txBuffer[9] = (DOIP_ENTITY_SA >> 0) & 0xff;
	txBuffer[10] = (DOIP_ENTITY_TA >> 8) & 0xff;
	txBuffer[11] = (DOIP_ENTITY_TA >> 0) & 0xff;
    
	txBuffer[12] = 0x31;	// SID for routine contel
	txBuffer[13] = 0x01;	// Start Control
	
	txBuffer[14] = (id >> 8) & 0xFFU;	// mandatory ID bytes for erase
	txBuffer[15] = id & 0xFFU;	// mandatory Id bytes
	txBuffer[16] = 0x10;
	txBuffer[17] = 0x05;
	txBuffer[18] = 0x01;
	txBuffer[19] = 0x00;	// Installer Type
	txBuffer[20] = 0x01;	// Installer Type
	for (i = 0; i < 16; i++)
	{
		txBuffer[21 + i] = 0xFF;
	}	
	
	error = send(tcpSockFd, &txBuffer[0], DOIP_HEADER_LEN+29, 0);
	
	if (error  < 0)
    {		
		printf("TCP connection sending extend session request failed... closing. error = %d\n", error);
		close (tcpSockFd);
		exit(EXIT_FAILURE);
	}

	printf("sent routine control request len = %d\n", error);
	
	printf("======================================\n");
	printf("Source Logical address: 0x");
	for (i=0; i< 2; i++)
	{
		printf("%02x", txBuffer[8 + i]);
	}				
	printf("\n");
	
	printf("Destination Logical address: 0x");
	for (i=0; i< 2; i++)
	{
		printf("%02x", txBuffer[10 + i]);
	}
	printf("\n");
									
	printf("UDS service  ID: 0x%02x\n", txBuffer[12]);
	
    printf("UDS service sub-id ID: 0x%02x\n", txBuffer[13]);
	
	printf("Rotuine Data Identifier: 0x");
	for (i=0; i< 2; i++)
	{
		printf("%02x", txBuffer[14 + i]);
	}
	printf("\n");
	
	printf("Write Data : 0x");
	for (i=0; i< 4; i++)
	{
		printf("%02x", txBuffer[16 + i]);
	}
	printf("\n");
	
	printf("======================================\n");
	
readAgain:
	if ((rxBytes = read(tcpSockFd, &readBuf[0], sizeof(readBuf))) <= 0)
	{		
		printf("TCP connection closed  or error = %d\n", rxBytes);
		close (tcpSockFd);
		exit(EXIT_FAILURE);
	}
	else
    {
		printf("Received read by ID ack/respone = %u\n", rxBytes);		
		for(i=0; i < rxBytes; i++)
		{
			printf("0x%02x ", readBuf[i]);
		}
		printf("\n");
		// DOIP ACK response 13 bytes 
		// write data by ID response 19 bytes
		if ((rxBytes == 13) || (rxBytes == 15) || (rxBytes == 20)) 
		{
			pass++;
		}
		else if (rxBytes == 17) {
			pass = 3;
		}
		else if (rxBytes == 28) // Two reponses came together.. Todo: Handle this in betterway
		{
			pass = 2;
		}
		else if (rxBytes == 35) // Two reponses came together.. Todo: Handle this in betterway
		{
			pass = 2;
		}
		else if (rxBytes == 48) // Three reponses came together.. Todo: Handle this in betterway
		{
			pass = 3;
		}
		else
		{
			printf("sendReadByID: unexpected response received.\n");
			close (tcpSockFd);
			exit(EXIT_FAILURE);
		}

		if ((pass == 3) && ((rxBytes ==  20) || (rxBytes == 35)))
		{

            uint8_t offset;

            offset = (rxBytes ==  35) ? 20: 0;
        
			printf("Response for Rtn Control request: \n");
			printf("======================================\n");
			printf("Source Logical address: 0x");
			for (i=0; i< 2; i++)
			{
				printf("%02x", readBuf[offset + 8 + i]);
			}				
			printf("\n");
			
			printf("Destination Logical address: 0x");
			for (i=0; i< 2; i++)
			{
				printf("%02x", readBuf[offset + 10 + i]);
			}
			printf("\n");
											
			printf("UDS service Routine SID: 0x%02x\n", readBuf[offset + 12]);
			
			printf("UDS service Routine Sub-ID: 0x%02x\n", readBuf[offset + 13]);
			
			printf("Routine Identifier: 0x");
			for (i=0; i< 2; i++)
			{
				printf("%02x", readBuf[offset + 14 + i]);
			}
			printf("\n");
			printf("======================================\n");
			
			printf("Routine Identifier response data : 0x");
			for (i=0; i< 4; i++)
			{
				printf("%02x", readBuf[offset + 16 + i]);
			}
			printf("\n");
			printf("======================================\n");
			
			
		}
		if (pass < 3)
	    {
			goto readAgain;
		}
	}
}

static void sendCheckProgrammingIntegrity() {
uint8_t txBuffer[128] = {0};
	uint8_t readBuf[512];
	int error;
	uint8_t pass = 0;
	int rxBytes;
	uint8_t i;
	uint16_t id = 0x0211;
	
	txBuffer[0] = 0x02;
	txBuffer[1] = ~0x02;
	txBuffer[2] = 0x80;
	txBuffer[3] = 0x01; // Diag message
	txBuffer[4] = 0;	
	txBuffer[5] = 0;
	txBuffer[6] = 0;
	txBuffer[7] = 24;   // bytes
	
	txBuffer[8] = (DOIP_ENTITY_SA >> 8) & 0xff;
	txBuffer[9] = (DOIP_ENTITY_SA >> 0) & 0xff;
	txBuffer[10] = (DOIP_ENTITY_TA >> 8) & 0xff;
	txBuffer[11] = (DOIP_ENTITY_TA >> 0) & 0xff;
    
	txBuffer[12] = 0x31;	// SID for routine contel
	txBuffer[13] = 0x01;	// Start Control
	
	txBuffer[14] = (id >> 8) & 0xFFU;	// mandatory ID bytes for erase
	txBuffer[15] = id & 0xFFU;	// mandatory Id bytes
	// txBuffer[16] = 0x10;
	// txBuffer[17] = 0x05;
	// txBuffer[18] = 0x01;
	// txBuffer[19] = 0x00;	// Installer Type
	// txBuffer[20] = 0x01;	// Installer Type
	for (i = 0; i < 16; i++)
	{
		txBuffer[16 + i] = 0xFF;
	}	
	
	error = send(tcpSockFd, &txBuffer[0], DOIP_HEADER_LEN+24, 0);
	
	if (error  < 0)
    {		
		printf("TCP connection sending extend session request failed... closing. error = %d\n", error);
		close (tcpSockFd);
		exit(EXIT_FAILURE);
	}

	printf("sent routine control request len = %d\n", error);
	
	printf("======================================\n");
	printf("Source Logical address: 0x");
	for (i=0; i< 2; i++)
	{
		printf("%02x", txBuffer[8 + i]);
	}				
	printf("\n");
	
	printf("Destination Logical address: 0x");
	for (i=0; i< 2; i++)
	{
		printf("%02x", txBuffer[10 + i]);
	}
	printf("\n");
									
	printf("UDS service  ID: 0x%02x\n", txBuffer[12]);
	
    printf("UDS service sub-id ID: 0x%02x\n", txBuffer[13]);
	
	printf("Rotuine Data Identifier: 0x");
	for (i=0; i< 2; i++)
	{
		printf("%02x", txBuffer[14 + i]);
	}
	printf("\n");
	
	printf("Write Data : 0x");
	for (i=0; i< 4; i++)
	{
		printf("%02x", txBuffer[16 + i]);
	}
	printf("\n");
	
	printf("======================================\n");
	
readAgain:
	if ((rxBytes = read(tcpSockFd, &readBuf[0], sizeof(readBuf))) <= 0)
	{		
		printf("TCP connection closed  or error = %d\n", rxBytes);
		close (tcpSockFd);
		exit(EXIT_FAILURE);
	}
	else
    {
		printf("Received read by ID ack/respone = %u\n", rxBytes);		
		for(i=0; i < rxBytes; i++)
		{
			printf("0x%02x ", readBuf[i]);
		}
		printf("\n");
		// DOIP ACK response 13 bytes 
		// write data by ID response 19 bytes
		if ((rxBytes == 13) || (rxBytes == 15) || (rxBytes == 20)) 
		{
			pass++;
		}
		else if (rxBytes == 17) {
			pass = 3;
		}
		else if (rxBytes == 28) // Two reponses came together.. Todo: Handle this in betterway
		{
			pass = 2;
		}
		else if (rxBytes == 35) // Two reponses came together.. Todo: Handle this in betterway
		{
			pass = 2;
		}
		else if (rxBytes == 48) // Three reponses came together.. Todo: Handle this in betterway
		{
			pass = 3;
		}
		else
		{
			printf("sendReadByID: unexpected response received.\n");
			close (tcpSockFd);
			exit(EXIT_FAILURE);
		}

		if ((pass == 3) && ((rxBytes ==  20) || (rxBytes == 35)))
		{

            uint8_t offset;

            offset = (rxBytes ==  35) ? 20: 0;
        
			printf("Response for Rtn Control request: \n");
			printf("======================================\n");
			printf("Source Logical address: 0x");
			for (i=0; i< 2; i++)
			{
				printf("%02x", readBuf[offset + 8 + i]);
			}				
			printf("\n");
			
			printf("Destination Logical address: 0x");
			for (i=0; i< 2; i++)
			{
				printf("%02x", readBuf[offset + 10 + i]);
			}
			printf("\n");
											
			printf("UDS service Routine SID: 0x%02x\n", readBuf[offset + 12]);
			
			printf("UDS service Routine Sub-ID: 0x%02x\n", readBuf[offset + 13]);
			
			printf("Routine Identifier: 0x");
			for (i=0; i< 2; i++)
			{
				printf("%02x", readBuf[offset + 14 + i]);
			}
			printf("\n");
			printf("======================================\n");
			
			printf("Routine Identifier response data : 0x");
			for (i=0; i< 4; i++)
			{
				printf("%02x", readBuf[offset + 16 + i]);
			}
			printf("\n");
			printf("======================================\n");
			
			
		}
		if (pass < 3)
	    {
			goto readAgain;
		}
	}
}

static void sendRtnCtrl_Start(uint16_t id)
{
	uint8_t txBuffer[128] = {0};
	uint8_t readBuf[512];
	int error;
	uint8_t pass = 0;
	int rxBytes;
	uint8_t i;
	
	txBuffer[0] = 0x02;
	txBuffer[1] = ~0x02;
	txBuffer[2] = 0x80;
	txBuffer[3] = 0x01; // Diag message
	txBuffer[4] = 0;	
	txBuffer[5] = 0;
	txBuffer[6] = 0;
	txBuffer[7] = 8;   // bytes
	
	txBuffer[8] = (DOIP_ENTITY_SA >> 8) & 0xff;
	txBuffer[9] = (DOIP_ENTITY_SA >> 0) & 0xff;
	txBuffer[10] = (DOIP_ENTITY_TA >> 8) & 0xff;
	txBuffer[11] = (DOIP_ENTITY_TA >> 0) & 0xff;
    
	txBuffer[12] = 0x31;	// SID for routine contel
	txBuffer[13] = 0x01;	// Start Control
	
	txBuffer[14] = (id >> 8) & 0xFFU;	// mandatory ID bytes for erase
	txBuffer[15] = id & 0xFFU;	// mandatory Id bytes
	
	// txBuffer[16] = 0x11;
	// txBuffer[17] = 0x22;
	// txBuffer[18] = 0x33;
	// txBuffer[19] = 0x44;
	
	
	error = send(tcpSockFd, &txBuffer[0], DOIP_HEADER_LEN+8, 0);
	
	if (error  < 0)
    {		
		printf("TCP connection sending extend session request failed... closing. error = %d\n", error);
		close (tcpSockFd);
		exit(EXIT_FAILURE);
	}

	printf("sent routine control request len = %d\n", error);
	
	printf("======================================\n");
	printf("Source Logical address: 0x");
	for (i=0; i< 2; i++)
	{
		printf("%02x", txBuffer[8 + i]);
	}				
	printf("\n");
	
	printf("Destination Logical address: 0x");
	for (i=0; i< 2; i++)
	{
		printf("%02x", txBuffer[10 + i]);
	}
	printf("\n");
									
	printf("UDS service  ID: 0x%02x\n", txBuffer[12]);
	
    printf("UDS service sub-id ID: 0x%02x\n", txBuffer[13]);
	
	printf("Rotuine Data Identifier: 0x");
	for (i=0; i< 2; i++)
	{
		printf("%02x", txBuffer[14 + i]);
	}
	printf("\n");
	
	printf("Write Data : 0x");
	for (i=0; i< 4; i++)
	{
		printf("%02x", txBuffer[16 + i]);
	}
	printf("\n");
	
	printf("======================================\n");
	
readAgain:
	if ((rxBytes = read(tcpSockFd, &readBuf[0], sizeof(readBuf))) <= 0)
	{		
		printf("TCP connection closed  or error = %d\n", rxBytes);
		close (tcpSockFd);
		exit(EXIT_FAILURE);
	}
	else
    {
		printf("Received read by ID ack/respone = %u\n", rxBytes);		
		for(i=0; i < rxBytes; i++)
		{
			printf("0x%02x ", readBuf[i]);
		}
		printf("\n");
		// DOIP ACK response 13 bytes 
		// write data by ID response 19 bytes
		if ((rxBytes == 13) || (rxBytes == 15) || (rxBytes == 20)) 
		{
			pass++;
		}
		else if (rxBytes == 17) {
			pass = 3;
		}
		else if (rxBytes == 28) // Two reponses came together.. Todo: Handle this in betterway
		{
			pass = 2;
		}
		else if (rxBytes == 35) // Two reponses came together.. Todo: Handle this in betterway
		{
			pass = 2;
		}
		else if (rxBytes == 48) // Three reponses came together.. Todo: Handle this in betterway
		{
			pass = 3;
		}
		else
		{
			printf("sendReadByID: unexpected response received.\n");
			close (tcpSockFd);
			exit(EXIT_FAILURE);
		}

		if ((pass == 3) && ((rxBytes ==  20) || (rxBytes == 35)))
		{

            uint8_t offset;

            offset = (rxBytes ==  35) ? 20: 0;
        
			printf("Response for Rtn Control request: \n");
			printf("======================================\n");
			printf("Source Logical address: 0x");
			for (i=0; i< 2; i++)
			{
				printf("%02x", readBuf[offset + 8 + i]);
			}				
			printf("\n");
			
			printf("Destination Logical address: 0x");
			for (i=0; i< 2; i++)
			{
				printf("%02x", readBuf[offset + 10 + i]);
			}
			printf("\n");
											
			printf("UDS service Routine SID: 0x%02x\n", readBuf[offset + 12]);
			
			printf("UDS service Routine Sub-ID: 0x%02x\n", readBuf[offset + 13]);
			
			printf("Routine Identifier: 0x");
			for (i=0; i< 2; i++)
			{
				printf("%02x", readBuf[offset + 14 + i]);
			}
			printf("\n");
			printf("======================================\n");
			
			printf("Routine Identifier response data : 0x");
			for (i=0; i< 4; i++)
			{
				printf("%02x", readBuf[offset + 16 + i]);
			}
			printf("\n");
			printf("======================================\n");
			
			
		}
		if (pass < 3)
	    {
			goto readAgain;
		}
	}
}


static void sendRtnCtrl_Stop(uint16_t id)
{
	uint8_t txBuffer[128] = {0};
	uint8_t readBuf[512];
	int error;
	uint8_t pass = 0;
	int rxBytes;
	uint8_t i;
	
	txBuffer[0] = 0x02;
	txBuffer[1] = ~0x02;
	txBuffer[2] = 0x80;
	txBuffer[3] = 0x01; // Diag message
	txBuffer[4] = 0;	
	txBuffer[5] = 0;
	txBuffer[6] = 0;
	txBuffer[7] = 8;   // bytes
	
	txBuffer[8] = (DOIP_ENTITY_SA >> 8) & 0xff;
	txBuffer[9] = (DOIP_ENTITY_SA >> 0) & 0xff;
	txBuffer[10] = (DOIP_ENTITY_TA >> 8) & 0xff;
	txBuffer[11] = (DOIP_ENTITY_TA >> 0) & 0xff;
    
	txBuffer[12] = 0x31;	// SID for routine contel
	txBuffer[13] = 0x02;	// stop
	
	txBuffer[14] = (id >> 8) & 0xFFU;	// mandatory ID bytes for erase
	txBuffer[15] = id & 0xFFU;	// mandatory Id bytes
		
	
	error = send(tcpSockFd, &txBuffer[0], DOIP_HEADER_LEN+8, 0);
	
	if (error  < 0)
    {		
		printf("TCP connection sending extend session request failed... closing. error = %d\n", error);
		close (tcpSockFd);
		exit(EXIT_FAILURE);
	}

	printf("sent routine control request len = %d\n", error);
	
	printf("======================================\n");
	printf("Source Logical address: 0x");
	for (i=0; i< 2; i++)
	{
		printf("%02x", txBuffer[8 + i]);
	}				
	printf("\n");
	
	printf("Destination Logical address: 0x");
	for (i=0; i< 2; i++)
	{
		printf("%02x", txBuffer[10 + i]);
	}
	printf("\n");
									
	printf("UDS service  ID: 0x%02x\n", txBuffer[12]);
	
    printf("UDS service sub-id ID: 0x%02x\n", txBuffer[13]);
	
	printf("Rotuine Data Identifier: 0x");
	for (i=0; i< 2; i++)
	{
		printf("%02x", txBuffer[14 + i]);
	}
	printf("\n");
	
	printf("======================================\n");
	
readAgain:
	if ((rxBytes = read(tcpSockFd, &readBuf[0], sizeof(readBuf))) <= 0)
	{		
		printf("TCP connection closed  or error = %d\n", rxBytes);
		close (tcpSockFd);
		exit(EXIT_FAILURE);
	}
	else
    {
		printf("Received read by ID ack/respone = %u\n", rxBytes);		
		for(i=0; i < rxBytes; i++)
		{
			printf("0x%02x ", readBuf[i]);
		}
		printf("\n");
		// DOIP ACK response 13 bytes 
		// write data by ID response 19 bytes
		if ((rxBytes == 13) || (rxBytes == 16)) 
		{
			pass++;
		}
		else if (rxBytes == 29) // Two reponses came together.. Todo: Handle this in betterway
		{
			pass = 2;
		}
		else
		{
			printf("sendReadByID: unexpected response received.\n");
			close (tcpSockFd);
			exit(EXIT_FAILURE);
		}

		if ((pass == 2) && ((rxBytes ==  13) || (rxBytes == 29)))
		{

            uint8_t offset;

            offset = (rxBytes ==  29) ? 13: 0;
        
			printf("Response for Rtn Control request: \n");
			printf("======================================\n");
			printf("Source Logical address: 0x");
			for (i=0; i< 2; i++)
			{
				printf("%02x", readBuf[offset + 8 + i]);
			}				
			printf("\n");
			
			printf("Destination Logical address: 0x");
			for (i=0; i< 2; i++)
			{
				printf("%02x", readBuf[offset + 10 + i]);
			}
			printf("\n");
											
			printf("UDS service Routine SID: 0x%02x\n", readBuf[offset + 12]);
			
			printf("UDS service Routine Sub-ID: 0x%02x\n", readBuf[offset + 13]);
			
			printf("Routine Identifier: 0x");
			for (i=0; i< 2; i++)
			{
				printf("%02x", readBuf[offset + 14 + i]);
			}
			printf("\n");
			printf("======================================\n");
			
		}
		if (pass < 2)
	    {
			goto readAgain;
		}
	}
}

static void sendRtnCtrl_Status(uint16_t id)
{
	uint8_t txBuffer[128] = {0};
	uint8_t readBuf[512];
	int error;
	uint8_t pass = 0;
	int rxBytes;
	uint8_t i;
	
	txBuffer[0] = 0x02;
	txBuffer[1] = ~0x02;
	txBuffer[2] = 0x80;
	txBuffer[3] = 0x01; // Diag message
	txBuffer[4] = 0;	
	txBuffer[5] = 0;
	txBuffer[6] = 0;
	txBuffer[7] = 8;   // bytes
	
	txBuffer[8] = (DOIP_ENTITY_SA >> 8) & 0xff;
	txBuffer[9] = (DOIP_ENTITY_SA >> 0) & 0xff;
	txBuffer[10] = (DOIP_ENTITY_TA >> 8) & 0xff;
	txBuffer[11] = (DOIP_ENTITY_TA >> 0) & 0xff;
    
	txBuffer[12] = 0x31;	// SID for routine contel
	txBuffer[13] = 0x03;	// status
	
	txBuffer[14] = (id >> 8) & 0xFFU;	// mandatory ID bytes for erase
	txBuffer[15] = id & 0xFFU;	// mandatory Id bytes
		
	
	error = send(tcpSockFd, &txBuffer[0], DOIP_HEADER_LEN+8, 0);
	
	if (error  < 0)
    {		
		printf("TCP connection sending extend session request failed... closing. error = %d\n", error);
		close (tcpSockFd);
		exit(EXIT_FAILURE);
	}

	printf("sent routine control request len = %d\n", error);
	
	printf("======================================\n");
	printf("Source Logical address: 0x");
	for (i=0; i< 2; i++)
	{
		printf("%02x", txBuffer[8 + i]);
	}				
	printf("\n");
	
	printf("Destination Logical address: 0x");
	for (i=0; i< 2; i++)
	{
		printf("%02x", txBuffer[10 + i]);
	}
	printf("\n");
									
	printf("UDS service  ID: 0x%02x\n", txBuffer[12]);
	
    printf("UDS service sub-id ID: 0x%02x\n", txBuffer[13]);
	
	printf("Rotuine Data Identifier: 0x");
	for (i=0; i< 2; i++)
	{
		printf("%02x", txBuffer[14 + i]);
	}
	printf("\n");
	
	printf("======================================\n");
	
readAgain:
	if ((rxBytes = read(tcpSockFd, &readBuf[0], sizeof(readBuf))) <= 0)
	{		
		printf("TCP connection closed  or error = %d\n", rxBytes);
		close (tcpSockFd);
		exit(EXIT_FAILURE);
	}
	else
    {
		printf("Received read by ID ack/respone = %u\n", rxBytes);		
		for(i=0; i < rxBytes; i++)
		{
			printf("0x%02x ", readBuf[i]);
		}
		printf("\n");
		// DOIP ACK response 13 bytes 
		// write data by ID response 19 bytes
		if ((rxBytes == 13) || (rxBytes == 20)) 
		{
			pass++;
		}
		else if (rxBytes == 33) // Two reponses came together.. Todo: Handle this in betterway
		{
			pass = 2;
		}
		else
		{
			printf("sendReadByID: unexpected response received.\n");
			close (tcpSockFd);
			exit(EXIT_FAILURE);
		}

		if ((pass == 2) && ((rxBytes ==  20) || (rxBytes == 33)))
		{

            uint8_t offset;

            offset = (rxBytes ==  33) ? 13: 0;
        
			printf("Response for Rtn Control request: \n");
			printf("======================================\n");
			printf("Source Logical address: 0x");
			for (i=0; i< 2; i++)
			{
				printf("%02x", readBuf[offset + 8 + i]);
			}				
			printf("\n");
			
			printf("Destination Logical address: 0x");
			for (i=0; i< 2; i++)
			{
				printf("%02x", readBuf[offset + 10 + i]);
			}
			printf("\n");
											
			printf("UDS service Routine SID: 0x%02x\n", readBuf[offset + 12]);
			
			printf("UDS service Routine Sub-ID: 0x%02x\n", readBuf[offset + 13]);
			
			printf("Routine Identifier: 0x");
			for (i=0; i< 2; i++)
			{
				printf("%02x", readBuf[offset + 14 + i]);
			}
			printf("\n");
			printf("======================================\n");
			
			printf("Routine Identifier response data : 0x");
			for (i=0; i< 4; i++)
			{
				printf("%02x", readBuf[offset + 16 + i]);
			}
			printf("\n");
			printf("======================================\n");
			
		}
		if (pass < 2)
	    {
			goto readAgain;
		}
	}
}

static void sendDiagProgramSessnion(void)
{
	uint8_t txBuffer[14];
	uint8_t readBuf[512];
	int error;
	uint8_t pass = 0;
	int rxBytes;
	
	txBuffer[0] = 0x02;
	txBuffer[1] = ~0x02;
	txBuffer[2] = 0x80;
	txBuffer[3] = 0x01; // Diag message
	txBuffer[4] = 0;	
	txBuffer[5] = 0;
	txBuffer[6] = 0;
	txBuffer[7] = 6;   // 6 bytes length
	
	txBuffer[8] = (DOIP_ENTITY_SA >> 8) & 0xff;
	txBuffer[9] = (DOIP_ENTITY_SA >> 0) & 0xff;
	txBuffer[10] = (DOIP_ENTITY_TA >> 8) & 0xff;
	txBuffer[11] = (DOIP_ENTITY_TA >> 0) & 0xff;
    
	txBuffer[12] = 0x10;	// DiaSession congtrol
	txBuffer[13] = 0x02;	// Program session
	
	error = send(tcpSockFd, &txBuffer[0], DOIP_HEADER_LEN+6, 0);
	
	if (error  < 0)
    {		
		printf("TCP connection sending program session request failed... closing. error = %d\n", error);
		close (tcpSockFd);
		exit(EXIT_FAILURE);
	}

	printf("sent program session request len = %d\n", error);
	
readAgain:
	if ((rxBytes = read(tcpSockFd, &readBuf[0], sizeof(readBuf))) <= 0)
	{		
		printf("TCP connection closed  or error = %d\n", rxBytes);
		close (tcpSockFd);
		exit(EXIT_FAILURE);
	}
	else
    {
		printf("Received program session ack/respone = %u\n", rxBytes);		
		uint8_t i;
		for(i=0; i < rxBytes; i++)
		{
			printf("0x%02x ", readBuf[i]);
		}
		printf("\n");
		// DOIP ACK response 13 bytes 
		// program session response 18 bytes
		if ((rxBytes == 13) || (rxBytes == 18)) 
		{
			pass++;
		}
		else if (rxBytes == 31) // Two reponses came together.. Todo: Handle this in betterway
		{
			pass = 2;
		}
		else
		{
			printf("sendDiagProgramSessnion: unexpected response received.\n");
			close (tcpSockFd);
			exit(EXIT_FAILURE);
		}		
		
		if (pass < 2)
	    {
			goto readAgain;
		}
	}
}

static void sendDownloadReq(void)
{
	uint8_t txBuffer[25];
	uint8_t readBuf[512];
	int error;
	uint8_t noPackets = 0;
	int rxBytes;
    uint32_t toReadLength = 8;
    uint32_t readLength = 0;
    uint32_t payloadLength = 0;
    int32_t i;
		
	txBuffer[0] = 0x02;
	txBuffer[1] = ~0x02;
	txBuffer[2] = 0x80;
	txBuffer[3] = 0x01; // Diag message
	txBuffer[4] = 0;	
	txBuffer[5] = 0;
	txBuffer[6] = 0;
	txBuffer[7] = 15;   //  bytes length
	
	txBuffer[8] = (DOIP_ENTITY_SA >> 8) & 0xff;
	txBuffer[9] = (DOIP_ENTITY_SA >> 0) & 0xff;
	txBuffer[10] = (DOIP_ENTITY_TA >> 8) & 0xff;
	txBuffer[11] = (DOIP_ENTITY_TA >> 0) & 0xff;
    
	txBuffer[12] = 0x34;	// Request donwload
	txBuffer[13] = 0x00;	// No data format
	txBuffer[14] = 0x44;	// AddrandLength identifier
	txBuffer[15] = 0x00;  	// Addr MSB
	txBuffer[16] = 0x0E;  	// Addr 
	txBuffer[17] = 0x10;  	// Addr 
	txBuffer[18] = 0x00;  	// Addr LSB  - DOIP testing hardcoded
	txBuffer[19] = (DOIP_UPLOAD_DOWNLOAD_LENGTH >> 24) & 0xFFU;  	// Length MSB
	txBuffer[20] = (DOIP_UPLOAD_DOWNLOAD_LENGTH >> 16) & 0xFFU;  	// Length 
	txBuffer[21] = (DOIP_UPLOAD_DOWNLOAD_LENGTH >> 8) & 0xFFU;  	// Length 
	txBuffer[22] = (DOIP_UPLOAD_DOWNLOAD_LENGTH >> 0) & 0xFFU;  	// Length

    printf("================================================\n");
    
	error = send(tcpSockFd, &txBuffer[0], DOIP_HEADER_LEN+txBuffer[7], 0);
	
	if (error  < 0)
    {		
		printf("TCP connection sending download request failed... closing. error = %d\n", error);
		close (tcpSockFd);
		exit(EXIT_FAILURE);
	}

	printf("sendDownloadReq: sent download request len = %d\n", error);

    while (noPackets < 2)
    {
        if ((rxBytes = read(tcpSockFd, &readBuf[readLength], toReadLength)) <= 0)
        {		
        	printf("TCP connection closed  or error = %d\n", rxBytes);
        	close(tcpSockFd);
        	exit(EXIT_FAILURE);
        }
        
        if (readLength == 0)
        {
            printf("Packet No = %d: Header: ", noPackets+1);

            for(i=0; i < rxBytes; i++)
            {
                printf("0x%02x ", readBuf[i]);
            }

            printf("\n");

            readLength += rxBytes;

            payloadLength = (((uint32_t)readBuf[4]) << 24) | (((uint32_t)readBuf[5]) << 16) | 
                            (((uint32_t)readBuf[6]) <<  8) | (((uint32_t)readBuf[7]) <<  0);  
            toReadLength =  payloadLength;            
        }
        else
        {
            if (rxBytes == toReadLength)
            {
                printf("Packet No = %d: Data: ", noPackets+1);

                for(i=0; i < rxBytes; i++)
                {
                    printf("0x%02x ", readBuf[readLength + i]);
                }

                printf("\n");

                noPackets++;
				readLength += rxBytes;

                if ((noPackets == 1) && (readLength !=  13)) // DoIP ACK length 13 bytes
                {
                    printf("Expected packed length = 13 Received length = %u\n", readLength);
                    close(tcpSockFd);
                    exit(EXIT_FAILURE);
                }
                else if (noPackets == 2) //UDS Response
                {
                    if (readLength !=  16)
                    {
                        printf("Expected packed length = 16 Received length = %u\n", readLength);
                        close(tcpSockFd);
                        exit(EXIT_FAILURE);
                    }
                    else
                    {
						uint8_t sizeLenBytes, addrLenBytes, shift;

						addrLenBytes = readBuf[13] & 0x0FU; // It's reserved filed... it should be zero in case of upload
						sizeLenBytes = (readBuf[13] & 0xF0U) >> 4U;
						blockLength = 0;

						/* Extract the length for databuffer. */
						for(i = 0; i < sizeLenBytes; i++)
						{
							shift = ((sizeLenBytes - (1U + i)));
							blockLength |= (uint32_t)(((uint32_t)readBuf[14 + addrLenBytes + i] & (uint32_t)0xFFU) << ((uint32_t)(8U * shift)));
						}
						printf("Recevied upload blockLength = %u\n", blockLength);
						blockLength -= 2;  // Subtract two bytes for SID and sequence number
                    }                    
                }
                readLength = 0;
                toReadLength = 8; // read doip header for next packet                
            } 
            else
            {
                readLength += rxBytes;
				toReadLength -= rxBytes;
            }
        }
    } 

    printf("================================================\n");
	
}

static void sendReqDownloadDataTransfer(void)
{
	int32_t i=0;
	uint8_t txBuffer[14+DOIP_UPLOAD_DOWNLOAD_LENGTH];
	uint8_t offset = 0x50;
	uint8_t readBuf[512];
	int error;
	int rxBytes;

    int32_t sentLength = 0;
    uint8_t blkCount = 0;
    int32_t toSend = 0;
    uint32_t toReadLength = 8;
    uint32_t readLength = 0;
    uint32_t payloadLength = 0;
    uint8_t data = 0;
    uint8_t noPackets = 0;

    printf("================================================\n");
    
    while (sentLength < DOIP_UPLOAD_DOWNLOAD_LENGTH)
    {   
        if ((DOIP_UPLOAD_DOWNLOAD_LENGTH - sentLength) >= blockLength)
        {
            toSend = blockLength;
        }
        else
        {
            toSend = DOIP_UPLOAD_DOWNLOAD_LENGTH - sentLength;
        }

        toSend += 6; // 6 bytes for SA, TA, SID and SEQ No
        blkCount++;
		noPackets = 0;
    
    	txBuffer[0] = 0x02;
    	txBuffer[1] = ~0x02;
    	txBuffer[2] = 0x80;
    	txBuffer[3] = 0x01; // Diag message
    	txBuffer[4] = (toSend >> 24) & 0xFFU;	
    	txBuffer[5] = (toSend >> 16) & 0xFFU;	;
    	txBuffer[6] = (toSend >> 8) & 0xFFU;	
    	txBuffer[7] = (toSend >> 0) & 0xFFU;	  //  bytes length
    	
    	txBuffer[8] = (DOIP_ENTITY_SA >> 8) & 0xff;
    	txBuffer[9] = (DOIP_ENTITY_SA >> 0) & 0xff;
    	txBuffer[10] = (DOIP_ENTITY_TA >> 8) & 0xff;
    	txBuffer[11] = (DOIP_ENTITY_TA >> 0) & 0xff;
        
    	txBuffer[12] = 0x36;	// Request for data transfer
    	txBuffer[13] = blkCount;	// sequence counter
    	
    	for (i=0; i < (toSend - 6); i++)
        {
    		txBuffer[14 +i] =  data;
    		downloadData[sentLength + i] = data;
            data++;
    	}
    	
    	error = send(tcpSockFd, &txBuffer[0], DOIP_HEADER_LEN+ toSend, 0);
    	
    	if (error  < 0)
        {		
    		printf("TCP connection sending download data transfer failed... closing. error = %d\n", error);
    		close (tcpSockFd);
    		exit(EXIT_FAILURE);
    	}


    	printf("sendReqDownloadDataTransfer: sent download data transfer request len = %d\n", error);
    	
    	printf("DoIP header data: ");
    	for(i=0; i < DOIP_HEADER_LEN; i++)
    	{
    		printf("%02x ", txBuffer[i]);
    	}
    	printf("\n");
    	
    	printf("SA: ");
    	for(i=0; i < 2; i++)
    	{
    		printf("%02x", txBuffer[DOIP_HEADER_LEN + i]);
    	}
    	printf("\n");
    	
    	printf("TA: ");
    	for(i=0; i < 2; i++)
    	{
    		printf("%02x", txBuffer[DOIP_HEADER_LEN + 2 + i]);
    	}
    	printf("\n");
    	
    	printf("SID and Block number: ");
    	for(i=0; i < 2; i++)
    	{
    		printf("%02x ", txBuffer[DOIP_HEADER_LEN + 4 + i]);
    	}
    	printf("\n");

        /*
        	printf("sending data data: ");
        	for(i=0; i < DOIP_UPLOAD_DOWNLOAD_LENGTH; i++)
        	{
        		printf("%02X ", txBuffer[DOIP_HEADER_LEN + 6 + i]);
        	}
        	printf("\n");
        	printf("================================================\n");
        	
        	*/

        while (noPackets < 3)
        {
           if ((rxBytes = read(tcpSockFd, &readBuf[readLength], toReadLength)) <= 0)
           {       
               printf("TCP connection closed  or error = %d\n", rxBytes);
               close(tcpSockFd);
               exit(EXIT_FAILURE);
           }
           
           if (readLength == 0)
           {
               printf("Packet No = %d: Header: ", noPackets+1);

               for(i=0; i < rxBytes; i++)
               {
                   printf("0x%02x ", readBuf[i]);
               }

               printf("\n");

           
               readLength += rxBytes;

               payloadLength = (((uint32_t)readBuf[4]) << 24) | (((uint32_t)readBuf[5]) << 16) | 
                               (((uint32_t)readBuf[6]) <<  8) | (((uint32_t)readBuf[7]) <<  0);  
               toReadLength =  payloadLength;            
           }
           else
           {               
               if (rxBytes == toReadLength)
               {
                   printf("Packet No = %d: Data: ", noPackets+1);

                   for(i=0; i < rxBytes; i++)
                   {
                       printf("0x%02x ", readBuf[readLength + i]);
                   }

                   printf("\n");

                   noPackets++;
				   readLength += rxBytes;

                   if ((noPackets == 1) && (readLength !=  13)) // DoIP ACK length 13 bytes
                   {
                        printf("Expected packed length = 13 Received length = %u\n", readLength);
                        close(tcpSockFd);
                        exit(EXIT_FAILURE);
                   }
                   else if ((noPackets == 2) && (readLength !=  15)) //UDS Response pending
                   {
                        printf("Expected packed length = 15 Received length = %u\n", readLength);
                        close(tcpSockFd);
                        exit(EXIT_FAILURE);
                   }
                   else if ((noPackets == 3) && (readLength != 14)) //UDS Transfer data positive Reponse
                   {

                        printf("Expected packed length = 14 Received length = %u\n", readLength);
                        close(tcpSockFd);
                        exit(EXIT_FAILURE);
                   }
                   
                   readLength = 0;
                   toReadLength = 8; // read doip header for next packet                
               }
               else
               {
                    readLength += rxBytes;
					toReadLength -=  rxBytes;
               }
           }
        }
		
		sentLength += (toSend - 6);
    }  

    printf("================================================\n");
}

static void sendUploadReq(void)
{
	uint8_t txBuffer[25];
	uint8_t readBuf[512];
	int error;	
	uint8_t noPackets = 0;
	int rxBytes;
    uint32_t toReadLength = 8;
    uint32_t readLength = 0;
    uint32_t payloadLength = 0;
    int32_t i;
		
	
	txBuffer[0] = 0x02;
	txBuffer[1] = ~0x02;
	txBuffer[2] = 0x80;
	txBuffer[3] = 0x01; // Diag message
	txBuffer[4] = 0;	
	txBuffer[5] = 0;
	txBuffer[6] = 0;
	txBuffer[7] = 15;   //  bytes length
	
	txBuffer[8] = (DOIP_ENTITY_SA >> 8) & 0xff;
	txBuffer[9] = (DOIP_ENTITY_SA >> 0) & 0xff;
	txBuffer[10] = (DOIP_ENTITY_TA >> 8) & 0xff;
	txBuffer[11] = (DOIP_ENTITY_TA >> 0) & 0xff;
    
	txBuffer[12] = 0x35;	// Request upload
	txBuffer[13] = 0x00;	// No data format
	txBuffer[14] = 0x44;	// AddrandLength identifier
	txBuffer[15] = 0x00;  	// Addr MSB
	txBuffer[16] = 0x0E;  	// Addr 
	txBuffer[17] = 0x10;  	// Addr 
	txBuffer[18] = 0x00;  	// Addr LSB  - DOIP testing hardcoded
	txBuffer[19] = (DOIP_UPLOAD_DOWNLOAD_LENGTH >> 24) & 0xFFU;  	// Length MSB
	txBuffer[20] = (DOIP_UPLOAD_DOWNLOAD_LENGTH >> 16) & 0xFFU;  	// Length 
	txBuffer[21] = (DOIP_UPLOAD_DOWNLOAD_LENGTH >> 8) & 0xFFU;  	// Length 
	txBuffer[22] = (DOIP_UPLOAD_DOWNLOAD_LENGTH >> 0) & 0xFFU;  	// Length
	   
	printf("================================================\n");
		
	error = send(tcpSockFd, &txBuffer[0], DOIP_HEADER_LEN + txBuffer[7], 0);
	
	if (error  < 0)
    {		
		printf("TCP connection sending upload req failed... closing. error = %d\n", error);
		close (tcpSockFd);
		exit(EXIT_FAILURE);
	}

	printf("sendUploadReq: sent upload request len = %d\n", error);
	
	while (noPackets < 2)
    {
        if ((rxBytes = read(tcpSockFd, &readBuf[readLength], toReadLength)) <= 0)
        {		
        	printf("TCP connection closed  or error = %d\n", rxBytes);
        	close(tcpSockFd);
        	exit(EXIT_FAILURE);
        }
        
        if (readLength == 0)
        {
            printf("Packet No = %d: Header: ", noPackets+1);

            for(i=0; i < rxBytes; i++)
            {
                printf("0x%02x ", readBuf[i]);
            }

            printf("\n");

        
            readLength += rxBytes;

            payloadLength = (((uint32_t)readBuf[4]) << 24) | (((uint32_t)readBuf[5]) << 16) | 
                            (((uint32_t)readBuf[6]) <<  8) | (((uint32_t)readBuf[7]) <<  0);  
            toReadLength =  payloadLength;            
        }
        else
        {
            if (rxBytes == toReadLength)
            {
                printf("Packet No = %d: Data: ", noPackets+1);

                for(i=0; i < rxBytes; i++)
                {
                    printf("0x%02x ", readBuf[readLength + i]);
                }

                printf("\n");

                noPackets++;
				readLength += rxBytes;

                if ((noPackets == 1) && (readLength !=  13)) // DoIP ACK length 13 bytes
                {
                    printf("Expected packed length = 13 Received length = %u\n", readLength);
                    close(tcpSockFd);
                    exit(EXIT_FAILURE);
                }
                else if (noPackets == 2) //UDS Response
                {
                    if (readLength !=  16)
                    {
                        printf("Expected packed length = 15 Received length = %u\n", readLength);
                        close(tcpSockFd);
                        exit(EXIT_FAILURE);
                    }
                    else
                    {
						uint8_t sizeLenBytes, addrLenBytes, shift;
						
						addrLenBytes = readBuf[13] & 0x0FU; // It's reserved filed... it should be zero in case of upload
						sizeLenBytes = (readBuf[13] & 0xF0U) >> 4U;
						blockLength = 0;
						
						printf("addrLenBytes = %u sizeLenBytes = %u\n", addrLenBytes, sizeLenBytes);
						printf("readBuf[13] = 0x%02X readBuf[14] = 0x%02X readBuf[15] = 0x%02X\n", readBuf[13], readBuf[14], readBuf[15]);
						
						/* Extract the length for databuffer. */
						for(i = 0; i < sizeLenBytes; i++)
						{
							shift = sizeLenBytes - (1U + i);
							blockLength |= (uint32_t)(((uint32_t)readBuf[14 + addrLenBytes + i] & (uint32_t)0xFFU) << ((uint32_t)(8U * shift)));
						}
                        printf("Recevied upload blockLength = %u\n", blockLength);
                        blockLength -= 2;  // Subtract two bytes for SID and sequence number
                    }                    
                }
                readLength = 0;
                toReadLength = 8; // read doip header for next packet                
            } 
            else
            {
                readLength += rxBytes;
				toReadLength -= rxBytes;
            }
        }
    } 

    printf("================================================\n");
}

static void sendReqUploadDataTransfer(void)
{
	uint8_t txBuffer[14];
	uint8_t offset;
	uint8_t readBuf[512 + DOIP_UPLOAD_DOWNLOAD_LENGTH];
	int error;
	int32_t rxBytes;
	int32_t i = 0;
    int32_t recvLength = 0;
    uint8_t blkCount = 0;
    int32_t toRead = 0;
    uint32_t toReadLength = 8;
    uint32_t readLength = 0;
    uint32_t payloadLength = 0;
    uint8_t data = 0;
    uint8_t noPackets = 0;
	
	
	printf("================================================\n");
    
    while (recvLength < DOIP_UPLOAD_DOWNLOAD_LENGTH)
    {   		
        blkCount++;
		noPackets = 0;
   
		txBuffer[0] = 0x02;
		txBuffer[1] = ~0x02;
		txBuffer[2] = 0x80;
		txBuffer[3] = 0x01; // Diag message
		txBuffer[4] = 0;	
		txBuffer[5] = 0;
		txBuffer[6] = 0;
		txBuffer[7] = 6;   //  bytes length
		
		txBuffer[8] = (DOIP_ENTITY_SA >> 8) & 0xff;
		txBuffer[9] = (DOIP_ENTITY_SA >> 0) & 0xff;
		txBuffer[10] = (DOIP_ENTITY_TA >> 8) & 0xff;
		txBuffer[11] = (DOIP_ENTITY_TA >> 0) & 0xff;
		
		txBuffer[12] = 0x36;	// Request for data transfer
		txBuffer[13] = blkCount;	// sequence counter
			
    	error = send(tcpSockFd, &txBuffer[0], DOIP_HEADER_LEN+ 6, 0);
    	
    	if (error  < 0)
        {		
    		printf("TCP connection sending download data transfer failed... closing. error = %d\n", error);
    		close (tcpSockFd);
    		exit(EXIT_FAILURE);
    	}

    	printf("sendReqUploadDataTransfer: sent upload data transfer request len = %d\n", error);
    	
    	printf("DoIP header data: ");
    	for(i=0; i < DOIP_HEADER_LEN; i++)
    	{
    		printf("%02x ", txBuffer[i]);
    	}
    	printf("\n");
    	
    	printf("SA: ");
    	for(i=0; i < 2; i++)
    	{
    		printf("%02x", txBuffer[DOIP_HEADER_LEN + i]);
    	}
    	printf("\n");
    	
    	printf("TA: ");
    	for(i=0; i < 2; i++)
    	{
    		printf("%02x", txBuffer[DOIP_HEADER_LEN + 2 + i]);
    	}
    	printf("\n");
    	
    	printf("SID and Block number: ");
    	for(i=0; i < 2; i++)
    	{
    		printf("%02x ", txBuffer[DOIP_HEADER_LEN + 4 + i]);
    	}
    	printf("\n");
		

        while (noPackets < 2)
        {
		   // printf("readLength = %u toReadLength = %u\n", readLength, toReadLength);
           if ((rxBytes = read(tcpSockFd, &readBuf[readLength], toReadLength)) <= 0)
           {       
               printf("TCP connection closed  or error = %d\n", rxBytes);
               close(tcpSockFd);
               exit(EXIT_FAILURE);
           }
           
           if (readLength == 0)
           {
               printf("Packet No = %d: Header: ", noPackets+1);

               for(i=0; i < rxBytes; i++)
               {
                   printf("0x%02x ", readBuf[i]);
               }

               printf("\n");
           
               readLength += rxBytes;

               payloadLength = (((uint32_t)readBuf[4]) << 24) | (((uint32_t)readBuf[5]) << 16) | 
                               (((uint32_t)readBuf[6]) <<  8) | (((uint32_t)readBuf[7]) <<  0);  
               toReadLength =  payloadLength;   
			   //printf("payloadLength = %u\n", payloadLength);
           }
           else
           {  
			   // printf("readLength = %u rxBytes = %d toReadLength = %u\n", readLength, rxBytes, toReadLength);
			   
               if (rxBytes == toReadLength)
               {
                   printf("Packet No = %d: Data: ", noPackets+1);

                   for(i=0; i < rxBytes; i++)
                   {
                       printf("0x%02x ", readBuf[readLength + i]);
                   }

                   printf("\n");
				   

                   noPackets++;
				   
				   readLength += rxBytes;

                   if ((noPackets == 1) && (readLength !=  13)) // DoIP ACK length 13 bytes
                   {
                        printf("Expected packed length = 13 Received length = %u\n", readLength);
                        close(tcpSockFd);
                        exit(EXIT_FAILURE);
                   }
                   else if (noPackets == 2) //UDS Response pending
                   {
					   // In the current UDS implementation, upload is a hack.. not fully compliant
					   // blockLength is not respected
					   
						if (readLength  != (8+ 6 + DOIP_UPLOAD_DOWNLOAD_LENGTH))
						{					   
							printf("Expected packed length = %u Received length = %u\n", (8+ 6 + DOIP_UPLOAD_DOWNLOAD_LENGTH), readLength);
							close(tcpSockFd);
							exit(EXIT_FAILURE);
						}
						else
						{
						   recvLength = DOIP_UPLOAD_DOWNLOAD_LENGTH;
						   memcpy(&uploadData[0], &readBuf[14], DOIP_UPLOAD_DOWNLOAD_LENGTH);
						}
                   }
                   readLength = 0;
                   toReadLength = 8; // read doip header for next packet                
               }
               else
               {
                    readLength += rxBytes;
					toReadLength -= rxBytes;
               }
           }
        }
    }  

    printf("================================================\n");
}

static void sendTransferExit(void)
{
	uint8_t txBuffer[13];
	uint8_t readBuf[512];
	int error;
	int rxBytes;
    int32_t sentLength = 0;
    uint8_t blkCount = 0;
    int32_t toSend = 0;
    uint32_t toReadLength = 8;
    uint32_t readLength = 0;
    uint32_t payloadLength = 0;
    uint8_t data = 0;
    uint8_t noPackets = 0;
    int32_t i = 0;
	
	txBuffer[0] = 0x02;
	txBuffer[1] = ~0x02;
	txBuffer[2] = 0x80;
	txBuffer[3] = 0x01; // Diag message
	txBuffer[4] = 0;	
	txBuffer[5] = 0;
	txBuffer[6] = 0;
	txBuffer[7] = 5;   //  bytes length
	
	txBuffer[8] = (DOIP_ENTITY_SA >> 8) & 0xff;
	txBuffer[9] = (DOIP_ENTITY_SA >> 0) & 0xff;
	txBuffer[10] = (DOIP_ENTITY_TA >> 8) & 0xff;
	txBuffer[11] = (DOIP_ENTITY_TA >> 0) & 0xff;
    
	txBuffer[12] = 0x37;	// Transfer exit
	
	error = send(tcpSockFd, &txBuffer[0], DOIP_HEADER_LEN + 5, 0);
	
	if (error  < 0)
    {		
		printf("TCP connection sending upload req failed... closing. error = %d\n", error);
		close (tcpSockFd);
		exit(EXIT_FAILURE);
	}

    printf("================================================\n");

	printf("sendTransferExit: sent transfer exit request len = %d\n", error);
	

	while (noPackets < 2)
    {
       if ((rxBytes = read(tcpSockFd, &readBuf[readLength], toReadLength)) <= 0)
       {       
           printf("TCP connection closed  or error = %d\n", rxBytes);
           close(tcpSockFd);
           exit(EXIT_FAILURE);
       }
       
       if (readLength == 0)
       {
           printf("Packet No = %d: Header: ", noPackets+1);

           for(i=0; i < rxBytes; i++)
           {
               printf("0x%02x ", readBuf[i]);
           }

           printf("\n");

       
           readLength += rxBytes;

           payloadLength = (((uint32_t)readBuf[4]) << 24) | (((uint32_t)readBuf[5]) << 16) | 
                           (((uint32_t)readBuf[6]) <<  8) | (((uint32_t)readBuf[7]) <<  0);  
           toReadLength =  payloadLength;            
       }
       else
       {               
           if (rxBytes == toReadLength)
           {
               printf("Packet No = %d: Data: ", noPackets+1);

               for(i=0; i < rxBytes; i++)
               {
                   printf("0x%02x ", readBuf[readLength + i]);
               }

               printf("\n");

               noPackets++;
			   
			   readLength += rxBytes;

               if ((noPackets == 1) && (readLength !=  13)) // DoIP ACK length 13 bytes
               {
                    printf("Expected packed length = 13 Received length = %u\n", (readLength + rxBytes));
                    close(tcpSockFd);
                    exit(EXIT_FAILURE);
               }
               else if ((noPackets == 2) && (readLength !=  13)) //UDS positive response
               {
                    printf("Expected packed length = 15 Received length = %u\n", (readLength + rxBytes));
                    close(tcpSockFd);
                    exit(EXIT_FAILURE);
               }
               readLength = 0;
               toReadLength = 8; // read doip header for next packet                
           }
           else
           {
                readLength += rxBytes;
				toReadLength -= rxBytes;
           }
       }
    }

    printf("================================================\n");
        
}

static void sendRequestSeed(int seed)
{
	uint8_t txBuffer[128];
	uint8_t readBuf[512];
	uint8_t packetBuf[512];
	int lenght = 0;
	int packetNumber = 0;
	int error;
	int rxBytes;
	uint8_t pass = 0;
		
	txBuffer[0] = 0x02;
	txBuffer[1] = ~0x02;
	txBuffer[2] = 0x80;
	txBuffer[3] = 0x01; // Diag message
	txBuffer[4] = 0;	
	txBuffer[5] = 0;
	txBuffer[6] = 0;
	txBuffer[7] = 6;   // 6 bytes length
	
	txBuffer[8] = (DOIP_ENTITY_SA >> 8) & 0xff;
	txBuffer[9] = (DOIP_ENTITY_SA >> 0) & 0xff;
	txBuffer[10] = (DOIP_ENTITY_TA >> 8) & 0xff;
	txBuffer[11] = (DOIP_ENTITY_TA >> 0) & 0xff;
    
	txBuffer[12] = 0x27;	// Security Access
	txBuffer[13] = seed;	// Request seed
	
	error = send(tcpSockFd, &txBuffer[0], DOIP_HEADER_LEN+6, 0);
	
	if (error  < 0)
    {		
		printf("TCP connection sending SA request seed failed... closing. error = %d\n", error);
		close (tcpSockFd);
		exit(EXIT_FAILURE);
	}
	printf("sent reqSeed len = %d\n", error);
readAgain:	
	if ((rxBytes = read(tcpSockFd, &readBuf[0], sizeof(readBuf))) <= 0)
	{		
		printf("TCP connection closed  or error = %d\n", rxBytes);
		close (tcpSockFd);
		exit(EXIT_FAILURE);
	}
	else
    {
		printf("Received reqSeed ack/respone = %u\n", rxBytes);		
		uint8_t i;
		for(i=0; i < rxBytes; i++)
		{
			printf("0x%02x ", readBuf[i]);
		}
		printf("\n");
		// DOIP ACK response 13 bytes 
		// reqSeed response 17 bytes
		if (rxBytes == 13) 
		{
			pass++;
		}
		else if (rxBytes > 13)
		{
			while (rxBytes > 0)
			{
				packetNumber++;
				printf("packet %d: ", packetNumber);
				for (i=0; i< 4; i++)
				{
					lenght +=readBuf[4 + i] << (4*(3-i)); // 4 :payload lenght form bit 4. has 4 bytes.
				}
				printf("payloadlenght %d: \n", lenght);
				if (lenght == 0 ) 
				{
					lenght = 5; // if packet have no payload it is 13 bytes.
				}
				for (i=0; i<(lenght+DOIP_HEADER_LEN); i++) // 8 : DoIP header is 8 bytes
				{
					packetBuf[i] = readBuf[i];
					printf("0x%02x ", packetBuf[i]);
				}
				printf("\n");
				rxBytes -= (lenght+DOIP_HEADER_LEN);
				for (i=0; i<rxBytes; i++)
				{
					readBuf[i] = readBuf[lenght+DOIP_HEADER_LEN+i];
				}
				lenght = 0;
			}
			pass = 2;
		}
		else
		{
			printf("sendSA: unexpected response received.\n");
			close (tcpSockFd);
			exit(EXIT_FAILURE);
		}		
		
		if (pass < 2)
	    {
			goto readAgain;
		}
		
	}
}

static void sendSendKey(int keylevel, bool invalidKey)
{
	uint8_t txBuffer[128];
	uint8_t readBuf[512];
	uint8_t packetBuf[512];
	int lenght = 0;
	int packetNumber = 0;
	int error;
	int rxBytes;
	uint8_t pass = 0;
	uint8_t key[ISOUDS_SA_KEYLEN_LEVEL05];
	if (keylevel == 0x06) 
	{
		// ISOUDS_SACalKey05(&readBuf[14], &key[0]);
	} 
	else if (keylevel == 0x1A)
	{
		ISOUDS_SACalKey19(&readBuf[14], &key[0]);
	} 
	else
	{
		// Used for negative test case
		ISOUDS_SACalKey19(&readBuf[14], &key[0]);
	}
	
	if (invalidKey)
	{
			key[0] += 1;
	}

	txBuffer[0] = 0x02;
	txBuffer[1] = ~0x02;
	txBuffer[2] = 0x80;
	txBuffer[3] = 0x01; // Diag message
	txBuffer[4] = 0;	
	txBuffer[5] = 0;
	txBuffer[6] = 0;
	txBuffer[7] = 0x0A;   // 9 bytes length
	
	txBuffer[8] = (DOIP_ENTITY_SA >> 8) & 0xff;
	txBuffer[9] = (DOIP_ENTITY_SA >> 0) & 0xff;
	txBuffer[10] = (DOIP_ENTITY_TA >> 8) & 0xff;
	txBuffer[11] = (DOIP_ENTITY_TA >> 0) & 0xff;
    
	txBuffer[12] = 0x27;	// Security Access
	txBuffer[13] = keylevel;
		
	txBuffer[14] = key[0];
	txBuffer[15] = key[1];
	txBuffer[16] = key[2];
	txBuffer[17] = key[3];
	
	pass = 0;
	error = send(tcpSockFd, &txBuffer[0], DOIP_HEADER_LEN+10, 0);
	
	if (error  < 0)
    {		
		printf("TCP connection sending SA request seed failed... closing. error = %d\n", error);
		close (tcpSockFd);
		exit(EXIT_FAILURE);
	}
	
	printf("sent key len = %d\n", error);
	size_t i = 0;
	for (i = 0; i < DOIP_HEADER_LEN + 10; ++i) {
		printf("0x%02x ", txBuffer[i]);
	}
	printf("\n");

readAgain2:	
	if ((rxBytes = read(tcpSockFd, &readBuf[0], sizeof(readBuf))) <= 0)
	{		
		printf("TCP connection close error = %d\n", rxBytes);
		close (tcpSockFd);
		exit(EXIT_FAILURE);
	}
	else
    {
		printf("Received sendKey ack/respone = %u\n", rxBytes);		
		uint8_t i;
		for(i=0; i < rxBytes; i++)
		{
			printf("0x%02x ", readBuf[i]);
		}
		printf("\n");
		
		// DOIP ACK response 13 bytes 
		// sendKey response 14 bytes
        packetNumber = 0;
		if (rxBytes == 13) 
		{
			pass++;
		}
		else if (rxBytes > 13)
		{
			while (rxBytes > 0)
			{
				packetNumber++;
				printf("packet %d: ", packetNumber);
				for (i=0; i< 4; i++)
				{
					lenght +=readBuf[4 + i] << (4*(3-i)); // 4 :payload lenght form bit 4. has 4 bytes.
				}
				printf("payloadlenght %d: \n", lenght);
				if (lenght == 0 ) 
				{
					lenght = 5; // if packet have no payload it is 13 bytes.
				}
				for (i=0; i<(lenght+DOIP_HEADER_LEN); i++) // 8 : DoIP header is 8 bytes
				{
					packetBuf[i] = readBuf[i];
					printf("0x%02x ", packetBuf[i]);
				}
				printf("\n");
				rxBytes -= (lenght+DOIP_HEADER_LEN);
				for (i=0; i<rxBytes; i++)
				{
					readBuf[i] = readBuf[lenght+DOIP_HEADER_LEN+i];
				}
				lenght = 0;
			}
			pass = 2;
		}
		else
		{
			printf("sendSendKey: unexpected response received.\n");
			close (tcpSockFd);
			exit(EXIT_FAILURE);
		}		
		
		if (pass < 2)
	    {
			goto readAgain2;
		}
	}	
}

void TCP_Server_Init(void)
{
    int opt = 1;
    struct sockaddr_in serverAddr; 

	printf("TCP_Server_Init called\n");
	
    if ((tcpSockFd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("tcp server socket failed\n");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(tcpSockFd, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt)) < 0 )   
    {   
        printf("setsockopt failed\n"); 
        close(tcpSockFd);
        exit(EXIT_FAILURE);	
    } 

    //type of socket created  
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;        // at the moment only IPv4 
	inet_pton(AF_INET, DOIP_ENTITY_IPADDRESS, &(serverAddr.sin_addr));   
    serverAddr.sin_port = htons(DOIP_LISTENING_PORT);
	
	// connect the client socket to server socket 
    if (connect(tcpSockFd, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) != 0) 
	{ 
        printf("connection with the server failed...\n"); 
        close(tcpSockFd);
		exit(EXIT_FAILURE);	
    } 
    else
	{
        printf("connected to the server successful \n"); 
	}
}

static void sendRA(void)
{
	uint8_t txBuffer[DOIP_HEADER_LEN+11];
	uint8_t readBuf[512];
	int error;
	int rxBytes;
	
	txBuffer[0] = 0x02;
	txBuffer[1] = ~0x02;
	txBuffer[2] = 0x00;
	txBuffer[3] = 0x05; // RA payload type: 0x0005
	txBuffer[4] = 0;	
	txBuffer[5] = 0;
	txBuffer[6] = 0;
	txBuffer[7] = 0x0B;   // 7 bytes length
	
	txBuffer[8] = (DOIP_ENTITY_SA >> 8) & 0xff;
	txBuffer[9] = (DOIP_ENTITY_SA >> 0) & 0xff;
    
	txBuffer[10] = 0xE2; //RA type - default
	
	txBuffer[11] = 0x00;
	txBuffer[12] = 0x00;
	txBuffer[13] = 0x00;
	txBuffer[14] = 0x00;
	txBuffer[15] = 0xFF;
	txBuffer[16] = 0xFF;
	txBuffer[17] = 0xFF;
	txBuffer[18] = 0xFF;

	
	error = send(tcpSockFd, &txBuffer[0], DOIP_HEADER_LEN + 11, 0);
	
	if (error  < 0)
    {		
		printf("TCP connection sending RA request failed... closing\n");
		close (tcpSockFd);
		exit(EXIT_FAILURE);
	}

	printf("sent Routing activation request len = %d\n", DOIP_HEADER_LEN + 11);
	
	if ((rxBytes = read(tcpSockFd, &readBuf[0], sizeof(readBuf))) <= 0)
	{		
		printf("TCP connection closed  or error = %d\n", rxBytes);
		close (tcpSockFd);
		exit(EXIT_FAILURE);		
	}
	else
    {
		printf("Received Routing activation ack/respone = %u\n", rxBytes);		
		uint8_t i;
		for(i=0; i < rxBytes; i++)
		{
			printf("0x%02x ", readBuf[i]);
		}
		printf("\n");
		
		if (rxBytes != 21)
		{
			printf("sendRA: Received unexpected response.. exiting\n");
			exit(EXIT_FAILURE);
		}
	}
}

static void changeSessnion(uint8_t session)
{
	uint8_t txBuffer[14];
	uint8_t readBuf[512];
	int error;
	uint8_t pass = 0;
	int rxBytes;
	
	txBuffer[0] = 0x02;
	txBuffer[1] = ~0x02;
	txBuffer[2] = 0x80;
	txBuffer[3] = 0x01; // Diag message
	txBuffer[4] = 0;	
	txBuffer[5] = 0;
	txBuffer[6] = 0;
	txBuffer[7] = 6;   // 6 bytes length
	
	txBuffer[8] = (DOIP_ENTITY_SA >> 8) & 0xff;
	txBuffer[9] = (DOIP_ENTITY_SA >> 0) & 0xff;
	txBuffer[10] = (DOIP_ENTITY_TA >> 8) & 0xff;
	txBuffer[11] = (DOIP_ENTITY_TA >> 0) & 0xff;
    
	txBuffer[12] = 0x10;	// DiaSession congtrol
	txBuffer[13] = session;	
	
	error = send(tcpSockFd, &txBuffer[0], DOIP_HEADER_LEN+6, 0);
	
	if (error  < 0)
    {		
		printf("TCP connection sending extend session request failed... closing. error = %d\n", error);
		close (tcpSockFd);
		exit(EXIT_FAILURE);
	}

	printf("sent extend diag session request len = %d\n", error);
	
readAgain:
	if ((rxBytes = read(tcpSockFd, &readBuf[0], sizeof(readBuf))) <= 0)
	{		
		printf("TCP connection closed  or error = %d\n", rxBytes);
		close (tcpSockFd);
		exit(EXIT_FAILURE);
	}
	else
    {
		printf("Received extend diag session ack/respone = %u\n", rxBytes);		
		uint8_t i;
		for(i=0; i < rxBytes; i++)
		{
			printf("0x%02x ", readBuf[i]);
		}
		printf("\n");
		// DOIP ACK response 13 bytes 
		// extend diag session response 18 bytes
		if ((rxBytes == 13) || (rxBytes == 18)) 
		{
			pass++;
		}
		else if (rxBytes == 31) // Two reponses came together.. Todo: Handle this in betterway
		{
			pass = 2;
		}
		else
		{
			printf("sendDiagExtendSessnion: unexpected response received.\n");
			close (tcpSockFd);
			exit(EXIT_FAILURE);
		}		
		
		if (pass < 2)
	    {
			goto readAgain;
		}
	}
}


int main(void)
{
	int32_t i;
	
	TCP_Server_Init();
	
	sendRA();

	sendReadByID(0xF1BD);
	sendReadByID(0xF1BC);		
	
	sendDiagExtendSessnion();   // Extend diagnostic  session

	sendRequestSeed(0x19);
	sendSendKey(0x1A, false);	

	// sendSA();  // Secure access  - Unlock
	sendRtnCtrl_Start(0x0202);	// Check Programming Precondition
	
	sendDiagProgramSessnion();  // Change to program session

	sendSA(); // Secure access  - Unlock - Need to do it again after change of session

	sendWriteByID(0xF0FF);	// Fingerprint
	
	sendMd5check();			// MD5 Check
	close(tcpSockFd);
	return 0;	
	sendDownloadReq();  // Send Download request
	
	sendReqDownloadDataTransfer();  // Download the data
	
	sendTransferExit();	// Exit the download

	sendCheckProgrammingIntegrity();

	sendRtnCtrl_Start(ISOUDS_RTNID_PACK_SIGN_VERIFICAT);	// PackageSignatureVerification

	sendRtnCtrl_Start(ISOUDS_RTNID_START_INSTALLATION);	// Start Installation

	sendReadByID(ISOUDS_INSTALL_PROGRESS_ID_F1BA);
	// sendUploadReq();  // Make upload request
	
	// sendReqUploadDataTransfer();  // Perform upload
	
	// sendTransferExit();	 // Exit upload

	changeSessnion(ISOUDS_DS);

    if (!memcmp(&downloadData[0], &uploadData[0], DOIP_UPLOAD_DOWNLOAD_LENGTH))
    {
		printf("Test Succesful: Upload and Download Matached\n");		
	}
	else
	{
		printf("Test FAILED: Upload and Download NOT Matached\n");	
	}

	#if 0
	printf("Download data: ");
	for(i=0; i <  DOIP_UPLOAD_DOWNLOAD_LENGTH; i++)
	{
		printf("%02x ", downloadData[i]);
	}
	
	printf("\n");
	printf("Upload data: ");
	for(i=0; i <  DOIP_UPLOAD_DOWNLOAD_LENGTH; i++)
	{
		printf("%02x ", uploadData[i]);
	}
	
    printf("\n");
	#endif
	
	
	close(tcpSockFd);
	
	return 0;
}

