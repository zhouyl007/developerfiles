/**
 * file
 *
 * brief Empty user application template
 *
 */

/**
 * mainpage User Application template doxygen documentation
 *
 * par Empty user application template
 *
 * Bare minimum empty user application template
 *
 * par Content
 *
 * -# Include the ASF header files (through asf.h)
 * -# Minimal main function that starts with a call to board_init()
 * -# "Insert application code here" comment
 *-pipe -fno-strict-aliasing -Wall -Wstrict-prototypes -Wmissing-prototypes -Werror-implicit-function-declaration -Wpointer-arith -std=gnu99 -ffunction-sections -fdata-sections -Wchar-subscripts -Wcomment -Wformat=2 -Wimplicit-int -Wmain -Wparentheses -Wsequence-point -Wreturn-type -Wswitch -Wtrigraphs -Wunused -Wuninitialized -Wunknown-pragmas -Wfloat-equal -Wundef -Wshadow -Wbad-function-cast -Wwrite-strings -Wsign-compare -Waggregate-return  -Wmissing-declarations -Wformat -Wmissing-format-attribute -Wno-deprecated-declarations -Wpacked -Wredundant-decls -Wnested-externs -Wlong-long -Wunreachable-code -Wcast-align --param max-inline-insns-single=500
 */

/*
 * Include header files for all drivers that have been imported from
 * Atmel Software Framework (ASF).
 */
#include <hsf.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../example.h"

#if (EXAMPLE_USE_DEMO==SSL_TEST_DEMO)

#include <cyassl/openssl/ssl.h>
#include <cyassl/internal.h>
#include <cyassl/cyassl_config.h>
#include <cyassl/ctaocrypt/hmac.h>

EXTERNC const int hf_gpio_fid_to_pid_map_table[HFM_MAX_FUNC_CODE];

#ifdef __LPT230__
int g_module_id= HFM_TYPE_LPT230;

const int hf_gpio_fid_to_pid_map_table[HFM_MAX_FUNC_CODE]=
{
	HFM_NOPIN,		//HFGPIO_F_JTAG_TCK
	HFM_NOPIN,		//HFGPIO_F_JTAG_TDO
	HFM_NOPIN,		//HFGPIO_F_JTAG_TDI
	HFM_NOPIN,		//HFGPIO_F_JTAG_TMS
	HFM_NOPIN,		//HFGPIO_F_USBDP
	HFM_NOPIN,		//HFGPIO_F_USBDM
	LPx30_GPIO2,	//HFGPIO_F_UART0_TX
	LPx30_GPIO23,	//HFGPIO_F_UART0_RTS
	LPx30_GPIO1,	//HFGPIO_F_UART0_RX
	LPx30_GPIO22,	//HFGPIO_F_UART0_CTS
	
	HFM_NOPIN,  		//HFGPIO_F_SPI_MISO
	HFM_NOPIN,	  	//HFGPIO_F_SPI_CLK
	HFM_NOPIN,	  	//HFGPIO_F_SPI_CS
	HFM_NOPIN,  		//HFGPIO_F_SPI_MOSI
	
	HFM_NOPIN,		//HFGPIO_F_UART1_TX,
	HFM_NOPIN,		//HFGPIO_F_UART1_RTS,
	HFM_NOPIN,		//HFGPIO_F_UART1_RX,
	HFM_NOPIN,		//HFGPIO_F_UART1_CTS,
	
	LPx30_GPIO8,	//HFGPIO_F_NLINK
	LPx30_GPIO24,	//HFGPIO_F_NREADY
	LPx30_GPIO25,	//HFGPIO_F_NRELOAD
	HFM_NOPIN,	    	//HFGPIO_F_SLEEP_RQ
	HFM_NOPIN,	    	//HFGPIO_F_SLEEP_ON
	
	HFM_NOPIN,	    	//HFGPIO_F_WPS
	HFM_NOPIN,		//HFGPIO_F_RESERVE1
	HFM_NOPIN,		//HFGPIO_F_RESERVE2
	HFM_NOPIN,		//HFGPIO_F_RESERVE3
	HFM_NOPIN,		//HFGPIO_F_RESERVE4
	HFM_NOPIN,		//HFGPIO_F_RESERVE5
	
	HFM_NOPIN,	   	//HFGPIO_F_USER_DEFINE
};

#elif defined __LPT130__
int g_module_id= HFM_TYPE_LPT130;

const int hf_gpio_fid_to_pid_map_table[HFM_MAX_FUNC_CODE]=
{
	HFM_NOPIN,		//HFGPIO_F_JTAG_TCK
	HFM_NOPIN,		//HFGPIO_F_JTAG_TDO
	HFM_NOPIN,		//HFGPIO_F_JTAG_TDI
	HFM_NOPIN,		//HFGPIO_F_JTAG_TMS
	HFM_NOPIN,		//HFGPIO_F_USBDP
	HFM_NOPIN,		//HFGPIO_F_USBDM
	LPx30_GPIO2,	//HFGPIO_F_UART0_TX
	HFM_NOPIN,		//HFGPIO_F_UART0_RTS
	LPx30_GPIO1,	//HFGPIO_F_UART0_RX
	HFM_NOPIN,		//HFGPIO_F_UART0_CTS
	
	HFM_NOPIN,  		//HFGPIO_F_SPI_MISO
	HFM_NOPIN,	  	//HFGPIO_F_SPI_CLK
	HFM_NOPIN,	  	//HFGPIO_F_SPI_CS
	HFM_NOPIN,  		//HFGPIO_F_SPI_MOSI
	
	HFM_NOPIN,		//HFGPIO_F_UART1_TX,
	HFM_NOPIN,		//HFGPIO_F_UART1_RTS,
	HFM_NOPIN,		//HFGPIO_F_UART1_RX,
	HFM_NOPIN,		//HFGPIO_F_UART1_CTS,
	
	LPx30_GPIO22,	//HFGPIO_F_NLINK
	LPx30_GPIO23,	//HFGPIO_F_NREADY
	LPx30_GPIO3,	//HFGPIO_F_NRELOAD
	HFM_NOPIN,	    	//HFGPIO_F_SLEEP_RQ
	HFM_NOPIN,	    	//HFGPIO_F_SLEEP_ON
	
	HFM_NOPIN,	    	//HFGPIO_F_WPS
	HFM_NOPIN,		//HFGPIO_F_RESERVE1
	HFM_NOPIN,		//HFGPIO_F_RESERVE2
	HFM_NOPIN,		//HFGPIO_F_RESERVE3
	HFM_NOPIN,		//HFGPIO_F_RESERVE4
	HFM_NOPIN,		//HFGPIO_F_RESERVE5
	
	HFM_NOPIN,	   	//HFGPIO_F_USER_DEFINE
};

#elif defined __LPB130__
int g_module_id= HFM_TYPE_LPB130;

const int hf_gpio_fid_to_pid_map_table[HFM_MAX_FUNC_CODE]=
{
	HFM_NOPIN,		//HFGPIO_F_JTAG_TCK
	HFM_NOPIN,		//HFGPIO_F_JTAG_TDO
	HFM_NOPIN,		//HFGPIO_F_JTAG_TDI
	HFM_NOPIN,		//HFGPIO_F_JTAG_TMS
	HFM_NOPIN,		//HFGPIO_F_USBDP
	HFM_NOPIN,		//HFGPIO_F_USBDM
	LPx30_GPIO2,	//HFGPIO_F_UART0_TX
	LPx30_GPIO23,	//HFGPIO_F_UART0_RTS
	LPx30_GPIO1,	//HFGPIO_F_UART0_RX
	LPx30_GPIO22,	//HFGPIO_F_UART0_CTS
	
	HFM_NOPIN,  		//HFGPIO_F_SPI_MISO
	HFM_NOPIN,	  	//HFGPIO_F_SPI_CLK
	HFM_NOPIN,	  	//HFGPIO_F_SPI_CS
	HFM_NOPIN,  		//HFGPIO_F_SPI_MOSI
	
	HFM_NOPIN,		//HFGPIO_F_UART1_TX,
	HFM_NOPIN,		//HFGPIO_F_UART1_RTS,
	HFM_NOPIN,		//HFGPIO_F_UART1_RX,
	HFM_NOPIN,		//HFGPIO_F_UART1_CTS,
	
	LPx30_GPIO8,	//HFGPIO_F_NLINK
	LPx30_GPIO24,	//HFGPIO_F_NREADY
	LPx30_GPIO25,	//HFGPIO_F_NRELOAD
	HFM_NOPIN,	    	//HFGPIO_F_SLEEP_RQ
	HFM_NOPIN,	    	//HFGPIO_F_SLEEP_ON
	
	HFM_NOPIN,	    	//HFGPIO_F_WPS
	HFM_NOPIN,		//HFGPIO_F_RESERVE1
	HFM_NOPIN,		//HFGPIO_F_RESERVE2
	HFM_NOPIN,		//HFGPIO_F_RESERVE3
	HFM_NOPIN,		//HFGPIO_F_RESERVE4
	HFM_NOPIN,		//HFGPIO_F_RESERVE5
	
	HFM_NOPIN,	   	//HFGPIO_F_USER_DEFINE
};
#else
#error "invalid project !you must define module type(__LPT230__)"
#endif

enum{
	MY_SSLCONNECT = 2,
	MY_SSLWRITE = 3,
	MY_SSLREAD  = 4,
	MY_SSLFREESSL = 5,
	MY_SSLFREECTX = 6,
	MY_SSLIDLE = 11,
	MY_SSLCONNECTIdle = 12
};

char sas_1[82] = { 0 };
int sas_length_sr = 0;
int sas_length_sig = 0;

#if 0
char Azure_Key[2][46]={
	"d8oguEuCpvWz6osazD8hDmgiWUfBcdWFl+WAK36njUc=",              // senderkey 
	"QFhXYVD3G0XZNOhPHhUlRv2JDvZ1+0dYO/gG30QvFsI="               // DELETE  RootManageSharedAccessKey
};	
#else
char Azure_Key[50] = { 0 };
#endif

#if 0
char ssl_url[101]={ "aldesnamespace.servicebus.chinacloudapi.cn" };
#else
char ssl_url[101]={ 0 };
int ssl_length = 0;
#endif

char ssl_recvbuf[2048] = { 0 };

char isTransferdata = 0;
char isHmac_sha256 = 1;                             			// 
char isHmac_sha256state[5] = { "on" };
const byte base64Encode[] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
                              'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
                              'U', 'V', 'W', 'X', 'Y', 'Z',
                              'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
                              'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
                              'u', 'v', 'w', 'x', 'y', 'z',
                              '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
                              '+', '/'
                            };


/* porting assistance from yaSSL by Raphael HUCK */
int Base64_Encode(const byte* in, word32 inLen, byte* out, word32* outLen)
{
    word32 i = 0,
           j = 0,
           n = 0;   /* new line counter */

    word32 outSz = (inLen + 3 - 1) / 3 * 4;
	

    outSz += (outSz + 64 - 1) / 64;  /* new lines */

	
	
    if (outSz > *outLen) return  -173;
    
    while (inLen > 2) {
        byte b1 = in[j++];
        byte b2 = in[j++];
        byte b3 = in[j++];

        /* encoded idx */
        byte e1 = b1 >> 2;
        byte e2 = ((b1 & 0x3) << 4) | (b2 >> 4);
        byte e3 = ((b2 & 0xF) << 2) | (b3 >> 6);
        byte e4 = b3 & 0x3F;

        /* store */
        out[i++] = base64Encode[e1];
        out[i++] = base64Encode[e2];
        out[i++] = base64Encode[e3];
        out[i++] = base64Encode[e4];

        inLen -= 3;

        if ((++n % (64 / 4)) == 0 && inLen)
            out[i++] = '\n';
    }

    /* last integral */
    if (inLen) {
        int twoBytes = (inLen == 2);

        byte b1 = in[j++];
        byte b2 = (twoBytes) ? in[j++] : 0;

        byte e1 = b1 >> 2;
        byte e2 = ((b1 & 0x3) << 4) | (b2 >> 4);
        byte e3 =  (b2 & 0xF) << 2;

        out[i++] = base64Encode[e1];
        out[i++] = base64Encode[e2];
        out[i++] = (twoBytes) ? base64Encode[e3] : '=';
        out[i++] = '=';
    } 

    out[i++] = '\n';
		
    if (i != outSz)
        return -154; 
    *outLen = outSz;
		
		
    return 0; 
}

void Hmac_sha256toBase64(const byte * context,unsigned char length, byte *sig_out,const byte * secret_key)
{
	Hmac hmac;
	byte hash[SHA256_DIGEST_SIZE];
	
	//byte hash_out[44];
	byte sig_length = 45;           // ????44???,???????

	byte input[80];

	//byte signature[44] ={"BIp5VYulhwCL2DC2mpWwdvJk9bvFrGqzpWYxWjxa1Ys="};
	
	int i_copycount;
	for (i_copycount = 0; i_copycount < length ; i_copycount++)
		input[i_copycount] = context[i_copycount];

	
	HmacSetKey(&hmac, SHA256, secret_key, (word32)strlen( (const char *) secret_key));
	HmacUpdate(&hmac, (byte*)input,(word32)length);
	HmacFinal(&hmac, hash);
	
	Base64_Encode((const byte *) & hash[0],(word32)32,sig_out,(word32 *)( &sig_length));
}

int i_k = 0;
#if 0

unsigned int AddSignature(char *senddata,char * data)
{
	unsigned char text_length=0;
	
	byte hash_signature[45];                         // 44 ??×?·???×?oóò???ê? ??DD
	
	time_t expiry_time =0;
	unsigned char i_sig = 0;
	static unsigned int i_sigstart = 0;
		
	static unsigned char get_state=0;
	
	switch (get_state)
	{
		case 0:
			if(i_k == 0)
				i_sigstart = 0;
		
			if((!i_sigstart) && (memcmp(data + i_k, "sr=https", 8) == 0))   //   ìT3yoó?ú  2?í??D?? ??o?×ê?'
			{
				memcpy(sas_1,data + i_k + 3,80);
				get_state = 1;
				
				i_sigstart = 0;
			}
			else if(i_sigstart)
			{
				*(senddata + i_sigstart) = data[i_k];
				i_sigstart ++;
			}
			
		break;
		case 1:
			if(memcmp(data + i_k, "&sig=", 5) == 0)
			{
				memcpy(senddata,data,i_k + 5);
				
				i_sigstart = i_k + 5;
				
				get_state = 2; 
			}
			
		break;
		case 2:
			
			if(memcmp(data + i_k, "&se=", 4) == 0)
			{
				
				text_length = ((memcmp(data,"POST",4) == 0) ? 70:60);
				//sas_1[69] = '\n';
				sas_1[text_length -1] = '\n';
				
				expiry_time=time(NULL);
				
//				if(expiry_time > 1502968277)
//					sprintf( (char *)&sas_1[70],"%d",expiry_time);
//				else
//					memcpy(sas_1 + 70,data + i_k + 4,10);
				
				if(expiry_time > 1502968277)
					sprintf( (char *)&sas_1[text_length],"%d",expiry_time);
				else
					memcpy(sas_1 + text_length,data + i_k + 4,10);
				
				Hmac_sha256toBase64((const byte *)&sas_1[0],(text_length + 10),&hash_signature[0],(const byte *)&Azure_Key[((memcmp(data,"POST",4) == 0) ? 0:1)][0]);
				
				for(i_sig = 0; i_sig < 44; i_sig ++)
				{
					if(hash_signature[i_sig] == '+')
					{
						*(senddata + i_sigstart + i_sig) = '%';
						i_sigstart ++;
						*(senddata + i_sigstart + i_sig) = '2';
						i_sigstart ++;
						*(senddata + i_sigstart + i_sig) = 'b';
						
					}
					else if(hash_signature[i_sig] == '/')
					{
						*(senddata + i_sigstart + i_sig) = '%';
						i_sigstart ++;
						*(senddata + i_sigstart + i_sig) = '2';
						i_sigstart ++;
						*(senddata + i_sigstart + i_sig) = 'f';				
					}
					else if(hash_signature[i_sig] == '=')
					{
						*(senddata + i_sigstart + i_sig) = '%';
						i_sigstart ++;
						*(senddata + i_sigstart + i_sig) = '3';
						i_sigstart ++;
						*(senddata + i_sigstart + i_sig) = 'd';				
					}
					else
						*(senddata + i_sigstart + i_sig) = hash_signature[i_sig];
				}
				
				i_sigstart +=44;
				memcpy(senddata + i_sigstart,data + i_k,4);
				i_sigstart +=4;
				memcpy(senddata + i_sigstart,sas_1 + text_length,10);
				i_sigstart +=10;
				
				get_state = 3; 
				
			}
				
		break;
		
		case 3:
			
			
			if(memcmp(data + i_k, "&skn", 4)==0)
			{
				*(senddata + i_sigstart) = data[i_k];
				i_sigstart ++;
				
				get_state = 0; 
			}
			
		break;
		default:
		
		break;
		
	}
	
	return i_sigstart;

}

#endif

#if 1
unsigned int AddSignature(char *senddata,char * data)
{
	unsigned char text_length=0;
	
	byte hash_signature[45];                         // 44 ???,????? ??
	
	time_t expiry_time =0;
	unsigned char i_sig = 0;
	static unsigned int i_sigstart = 0;
	static unsigned char get_state=0;
	
	switch (get_state)
	{
		case 0:
			if(i_k == 0)
				i_sigstart = 0;
		
			if((!i_sigstart) && (memcmp(data + i_k, "sr=", 3) == 0))   //   ????  ???? ????
			{
				memcpy(sas_1,data + i_k + 3,80);
				get_state = 1;
				
				i_sigstart = 0;
			}
			else if(i_sigstart)
			{
				*(senddata + i_sigstart) = data[i_k];
				i_sigstart ++;
			}			
		break;
		case 1:
			if(memcmp(data + i_k, "&sig=", 5) == 0)
			{
				memcpy(senddata,data,i_k + 5);
				
				i_sigstart = i_k + 5;
				
				get_state = 2; 
			}			
		break;
		case 2:
			if(memcmp(data + i_k, "&se=", 4) == 0)
			{
				
				text_length = sas_length_sig - sas_length_sr - 2/*((memcmp(data,"POST",4) == 0) ? 70:60) */;
				//sas_1[69] = '\n';
				sas_1[text_length - 1] = '\n';
				
				expiry_time=time(NULL);
				
//				if(expiry_time > 1502968277)
//					sprintf( (char *)&sas_1[70],"%d",expiry_time);
//				else
//					memcpy(sas_1 + 70,data + i_k + 4,10);
				
				if(expiry_time > 1502968277)
					sprintf( (char *)&sas_1[text_length],"%d",expiry_time);
				else
					memcpy(sas_1 + text_length,data + i_k + 4,10);

				HF_Debug(DEBUG_LEVEL_LOW,"sas_1 = %s\n",&sas_1[0]);
				
				Hmac_sha256toBase64((const byte *)&sas_1[0],(text_length + 10),&hash_signature[0],(const byte *)&Azure_Key/*[((memcmp(data,"POST",4) == 0) ? 0:1)]*/[0]);
				
				for(i_sig = 0; i_sig < 44; i_sig ++)
				{
					if(hash_signature[i_sig] == '+')
					{
						*(senddata + i_sigstart + i_sig) = '%';
						i_sigstart ++;
						*(senddata + i_sigstart + i_sig) = '2';
						i_sigstart ++;
						*(senddata + i_sigstart + i_sig) = 'b';
						
					}
					else if(hash_signature[i_sig] == '/')
					{
						*(senddata + i_sigstart + i_sig) = '%';
						i_sigstart ++;
						*(senddata + i_sigstart + i_sig) = '2';
						i_sigstart ++;
						*(senddata + i_sigstart + i_sig) = 'f';				
					}
					else if(hash_signature[i_sig] == '=')
					{
						*(senddata + i_sigstart + i_sig) = '%';
						i_sigstart ++;
						*(senddata + i_sigstart + i_sig) = '3';
						i_sigstart ++;
						*(senddata + i_sigstart + i_sig) = 'd';				
					}
					else
						*(senddata + i_sigstart + i_sig) = hash_signature[i_sig];
				}
				
				i_sigstart +=44;
				memcpy(senddata + i_sigstart,data + i_k,4);
				i_sigstart +=4;
				memcpy(senddata + i_sigstart,sas_1 + text_length,10);
				i_sigstart +=10;
				
				get_state = 3; 
				
			}
		break;		
		case 3:
			if(memcmp(data + i_k, "&skn", 4)==0)
			{
				*(senddata + i_sigstart) = data[i_k];
				i_sigstart ++;
				
				get_state = 0; 
			}
	
		break;
		default:
		
		break;
		
	}
	
	return i_sigstart;
}

#endif

/* return 1 is a ipaddress */
int addressis_ip(const char * ipaddr)
{
	char ii, ipadd;
	int i, j;
	
	ii=0;
	for (j= 0; j< 4; j++)
	{
		ipadd=0;
		for (i=0; i< 4; i++, ii++)
		{
			if (*(ipaddr+ii)=='.')
				if (i== 0)
					return 0;		//the first shall not be '.'
				else
				{
					ii++;
					break;			//this feild finished
				}
			else if ((i==3)&&(j!=3))	//not the last feild, the number shall less than 4 bits
				return 0;
			else if ((*(ipaddr+ii) > '9')||(*(ipaddr+ii) < '0'))
			{
				if ((*(ipaddr+ii) == '\0')&&(j==3)&&(i!=0))
				{
					break;
				}
				else
					return 0;			//pls input number
			}
			else
				ipadd= ipadd*10+(*(ipaddr+ii)-'0');
			if (ipadd > 255)
				return 0;
		}
	}
	return 1;
}

int tcp_connect_ssl_server(char *url)
{
	int fd;	
	struct sockaddr_in addr;
	char *addrp=url;
	
	if((memcmp(url, "HTTPS://", 8)==0)||(memcmp(url, "https://", 8)==0))
		addrp= (char *)(url+8);

	ip_addr_t dest_addr;
	if(is_ipaddress((const char *)(addrp)) !=1 )
	{
		if(netconn_gethostbyname((const char *)(addrp), &dest_addr) !=HF_SUCCESS)
			return -1;
	}
	else
		inet_aton((char *)(addrp), (ip_addr_t *) &dest_addr);
	
	memset((char*)&addr,0,sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(443);
	addr.sin_addr.s_addr=dest_addr.addr;
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if(fd<0)
		return -1;
	
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr))< 0)
	{
		close(fd);
		return -1;
	}
	
	return fd;
}

#if 0
char sslsendbuf[1000] = {0};
int sslsendnum = 0;

static void my_ssl_task( void )
{
	static unsigned char READ_STDCOUNT = 2;
	static unsigned char my_sslState = MY_SSLIDLE;
	static unsigned char read_countout = 0;
	static unsigned char connect_timeout = 115;
	char temp[101] = {0};
	int recvlen = 0;
	int sockfd = -1;
	
	hffile_userbin_read(0, temp, 100);	
	if((temp[0] == 0x00) || (temp[0] == (char)0xff))
		hffile_userbin_write(0, ssl_url, strlen(ssl_url)+1);
	else
		hffile_userbin_read(0, ssl_url, 100);	
	
	
	hffile_userbin_read(101, temp, 5);		
	if((temp[0] == 0x00) || (temp[0] == (char)0xff))
		hffile_userbin_write(101,isHmac_sha256state, strlen(isHmac_sha256state)+1);
	else
	{
		hffile_userbin_read(101, isHmac_sha256state, 5);		
		if(memcmp(isHmac_sha256state, "on", 2)==0 || memcmp(isHmac_sha256state, "ON", 2)==0)
			isHmac_sha256 = 1;
		else if((memcmp(isHmac_sha256state, "off", 3)==0 || memcmp(isHmac_sha256state, "OFF", 3)==0))
			isHmac_sha256 = 0;
		else
			isHmac_sha256 = 1;
	}
	
	while(1)
	{
		switch(my_sslState)
		{
			
			case MY_SSLIDLE:

				if(isTransferdata)
				{
					my_sslState = MY_SSLCONNECT;
				  isTransferdata = 0;
					read_countout = 0;
					
					READ_STDCOUNT = 2;
				}
				else
				{
					msleep(30);
				}
				
			break;
			
			case MY_SSLCONNECTIdle:
				
				if(isTransferdata)
				{
					my_sslState = MY_SSLWRITE;
					isTransferdata = 0;
					read_countout = 0;
					
					READ_STDCOUNT  = 2;
				}
				else
				{
					if(read_countout > READ_STDCOUNT)
					{
						//msleep(30);
						my_sslState = MY_SSLFREESSL;                  // ??
					}
					else
						my_sslState = MY_SSLREAD;
				}
			break;
			
			case MY_SSLCONNECT:
			
				InitMemoryTracker();//for debug, it can show how many memory used in SSL
				CyaSSL_Debugging_ON();//for debug

				CyaSSL_Init();
				CYASSL_METHOD*  method  = 0;
				CYASSL_CTX*     ctx     = 0;
				CYASSL*         ssl     = 0;
				
			
				method=CyaTLSv1_client_method();//??SSL???method
				if (method == NULL)
					HF_Debug(DEBUG_LEVEL_LOW, "unable to get method");

				ctx = CyaSSL_CTX_new(method);//????????
				if (ctx == NULL)
				{
					HF_Debug(DEBUG_LEVEL_LOW, "unable to get ctx");
					
					my_sslState = MY_SSLIDLE;
					break;
				}
			/*	?????? SSL_VERIFY_NONE:?????	*/
				CyaSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);//disable verify certificates
			//???ssl	
				ssl = CyaSSL_new(ctx);
				if (ssl == NULL)
				{
					HF_Debug(DEBUG_LEVEL_LOW, "unable to get SSL object");
			//		goto FREE_CTX;
					my_sslState = MY_SSLFREECTX;
					break;
				}

				sockfd=tcp_connect_ssl_server(ssl_url);
				if(sockfd<0)
				{
					HF_Debug(DEBUG_LEVEL_LOW, "create socket error");
			//		goto FREE_SSL;
					my_sslState = MY_SSLFREESSL;
					break;
				}
				
				CyaSSL_set_fd(ssl, sockfd);
				if (CyaSSL_connect(ssl) != SSL_SUCCESS)
				{
					int  err = CyaSSL_get_error(ssl, 0);
					char buffer[80];
					HF_Debug(DEBUG_LEVEL_LOW, "err = %d, %s\n", err,CyaSSL_ERR_error_string(err, buffer));
					HF_Debug(DEBUG_LEVEL_LOW, "SSL_connect failed");
				}
			
			//break;      connect ??????
			
			case MY_SSLWRITE:
				
				if (CyaSSL_write(ssl, sslsendbuf, sslsendnum) != sslsendnum)
							HF_Debug(DEBUG_LEVEL_LOW,"SSL_write failed");

				memset(sslsendbuf,0,sslsendnum);
				sslsendnum = 0;

				HF_Debug(DEBUG_LEVEL_LOW,"Server response: recv start -------------------RESET------------------\n");
				my_sslState = MY_SSLREAD;
				
			break;
			
			case MY_SSLREAD:
				
				recvlen = CyaSSL_read(ssl, ssl_recvbuf, sizeof(ssl_recvbuf)-1);

				if(recvlen > 0)
				{
					
					if( (recvlen > 3) && ((memcmp(&ssl_recvbuf[0], "HTTP", 4)==0) || (memcmp(&ssl_recvbuf[0], "TTP/", 4)==0)))
					{
						
						read_countout = READ_STDCOUNT;
						
					}
					else
					{
						//  wait recv data  count or time?
						
						if(read_countout  == READ_STDCOUNT)      // ??????????? ???????
							READ_STDCOUNT = 20;
					}

					hfuart_send(HFUART0, ssl_recvbuf, recvlen,1536);
				
					my_sslState = MY_SSLCONNECTIdle;

					read_countout ++;
					
				}
				else if (recvlen < 0) 
				{
					int readErr = CyaSSL_get_error(ssl, 0);
					if (readErr != SSL_ERROR_WANT_READ)
						HF_Debug(DEBUG_LEVEL_LOW, "CyaSSL_read failed");
					
					my_sslState = MY_SSLFREESSL;
				}
				else
				{
					HF_Debug(DEBUG_LEVEL_LOW,"\n---------------------------------------- recv End!\n");	
					my_sslState = MY_SSLFREESSL;
				}
				

			
			break;
			
			case MY_SSLFREESSL://?????????
				
				CyaSSL_shutdown(ssl);
				CyaSSL_free(ssl);
			
				my_sslState = MY_SSLFREECTX;
			// break;  release to connect resource
			
			case MY_SSLFREECTX://?????????
				
				CyaSSL_CTX_free(ctx);
				close(sockfd);

				CyaSSL_Debugging_OFF();//close debug
				ShowMemoryTracker();//peek into how memory was used
			
				my_sslState = MY_SSLIDLE;
			break;
			
			default:
				
			break;
		}
	}

}

#else
//char ssl_url[101];
//char ssl_recvbuf[1000];

static void my_ssl_test(char *url, char *sendbuf, int sendnum)//a SSL test
{
	InitMemoryTracker();//for debug, it can show how many memory used in SSL
	CyaSSL_Debugging_ON();//for debug

	CyaSSL_Init();
	
	CYASSL_METHOD*  method  = 0;
	CYASSL_CTX*     ctx     = 0;
	CYASSL*         ssl     = 0;
	int sockfd = -1;
	struct timeval timeout;
	fd_set readfds;
	
	method = CyaTLSv1_2_client_method();
	if (method == NULL)
		HF_Debug(DEBUG_LEVEL_LOW, "unable to get method");

	ctx = CyaSSL_CTX_new(method);
	if (ctx == NULL)
	{
		HF_Debug(DEBUG_LEVEL_LOW, "unable to get ctx");
		return;
	}

	CyaSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);//disable verify certificates
	
	ssl = CyaSSL_new(ctx);
	if (ssl == NULL)
	{
		HF_Debug(DEBUG_LEVEL_LOW, "unable to get SSL object");
		goto FREE_CTX;
	}

	sockfd=tcp_connect_ssl_server(url);
	
	if(sockfd<0)
	{
		HF_Debug(DEBUG_LEVEL_LOW, "create socket error");
		goto FREE_SSL;
	}
	
	CyaSSL_set_fd(ssl, sockfd);
	if (CyaSSL_connect(ssl) != SSL_SUCCESS)
 	{
		int  err = CyaSSL_get_error(ssl, 0);
		char buffer[80];
		HF_Debug(DEBUG_LEVEL_LOW, "err = %d, %s\n", err,CyaSSL_ERR_error_string(err, buffer));
		HF_Debug(DEBUG_LEVEL_LOW, "SSL_connect failed");
	}
	else
		HF_Debug(DEBUG_LEVEL_LOW, "SSL_connect successed ----------------------------------------\n");

	if (CyaSSL_write(ssl, sendbuf, sendnum) != sendnum)
       	HF_Debug(DEBUG_LEVEL_LOW,"SSL_write failed");

	int recvlen = 0;
	int nfds;
	FD_ZERO(&readfds);
	FD_SET(sockfd,&readfds);
	timeout.tv_sec = 1;
	timeout.tv_usec = 0;
	nfds = sockfd + 1;

  recvlen = CyaSSL_read(ssl, ssl_recvbuf, sizeof(ssl_recvbuf)-1);
		
	if (recvlen > 0)
	{
		HF_Debug(DEBUG_LEVEL_LOW,"Server response: recv start %d----------------------------------------\n",recvlen);
		CyaSSL_Debugging_OFF();
		hfuart_send(HFUART0, ssl_recvbuf, recvlen,200); 
		
		int recvlen_;
		
		while (1) 
		{
			nfds = select(nfds,&readfds,NULL,NULL,&timeout);
			
			if(nfds > 0){
				recvlen_ += recvlen;
				recvlen = CyaSSL_read(ssl, ssl_recvbuf + recvlen_, sizeof(ssl_recvbuf)-1);
				
				if (recvlen > 0) 
					hfuart_send(HFUART0, ssl_recvbuf + recvlen_, recvlen,200);
				else
					break;
			}
			else
				break;
		}
		
		CyaSSL_Debugging_ON();
		HF_Debug(DEBUG_LEVEL_LOW,"\n---------------------------------------- recv End!\n");	
	}
	else if (recvlen < 0) 
	{
		int readErr = CyaSSL_get_error(ssl, 0);
		if (readErr != SSL_ERROR_WANT_READ)
			HF_Debug(DEBUG_LEVEL_LOW, "CyaSSL_read failed");
	}

FREE_SSL:
	CyaSSL_shutdown(ssl);
	CyaSSL_free(ssl);
FREE_CTX:
	CyaSSL_CTX_free(ctx);
	close(sockfd);
	
	CyaSSL_Debugging_OFF(); //close debug
	ShowMemoryTracker();    //peek into how memory was used
}
#endif

static USER_FUNC int get_manuf_id(pat_session_t s,int argc,char *argv[],char *rsp,int len)
{
	char oem_id[32] = "cubic_oaiq";
	
	if( 0 == argc )
	{
		hffile_userbin_read(0, oem_id, 100);	
		sprintf(rsp, "%s=%s", rsp, oem_id);
		return 0;
	}
	else if( 1 == argc )
	{
		if((strlen(argv[0]) > 1)&&(strlen(argv[0]) < 100))
		{
			hffile_userbin_write(0, argv[0], strlen(argv[0])+1);
			return 0;
		}
		else
			return -1;
	}
	else
		return -1;		
}

static USER_FUNC int set_ssl_addr(pat_session_t s,int argc,char *argv[],char *rsp,int len)
{
	if( 0 == argc )
	{
		hffile_userbin_read(0, ssl_url, 100);	
		sprintf(rsp, "%s=%s", rsp, ssl_url);
		return 0;
	}
	else if( 1 == argc )
	{
		if((strlen(argv[0]) > 1)&&(strlen(argv[0]) < 100))
		{
			hffile_userbin_write(0, argv[0], strlen(argv[0])+1);
			return 0;
		}
		else
			return -1;
	}
	else
		return -1;
		
}

const hfat_cmd_t user_define_at_cmds_table[]=
{
	{"SSLADDR", set_ssl_addr, "   AT+SSLADDR: Get/Set address for SSL.\r\n", NULL},//add a AT cmd for SSL
	{"MANUFID", get_manuf_id, "   AT+MANUF: Get/Set Manufacture ID.\r\n", NULL},
	{NULL,NULL,NULL,NULL} //the last item must be null
};

static int USER_FUNC uart_recv_callback(uint32_t event,char *data,uint32_t len,uint32_t buf_len)
{

	//if in AT cmd mode, return
	if(hfsys_get_run_mode() == HFSYS_STATE_RUN_CMD)
		return len;

	//HF_Debug(DEBUG_LEVEL_LOW,"[%d]uart recv %d bytes data %d\n",event,len,buf_len);
	if((memcmp(data, "POST", 4)==0)||(memcmp(data, "GET", 3)==0)||(memcmp(data, "DELETE", 6)==0))
	{
		
		char sslsendbuf[1024] = {0};
		int sslsendnum = 0;
		int offset = 0;
		int ssl_start = 0;
		int ssl_end = 0;
		int secret_start = 0;
		int secret_end = 0;
		unsigned char offset_cmp = 0;

		memset(ssl_url,0,sizeof(ssl_url));
		memset(Azure_Key,0,sizeof(Azure_Key));
		memset(sas_1,0,sizeof(sas_1));

		//hffile_userbin_read(0, ssl_url, 100);
		if(memcmp(data, "GET", 3)==0)
		{
			offset_cmp = 4;
		}
		if(memcmp(data, "POST", 4)==0)
		{
			offset_cmp = 5;
		}
		
		if(memcmp(data + offset_cmp, "/api/v1", 7) == 0)
		{
			while(memcmp(data + offset, "Host:", 5))
			{
				ssl_start = offset++;
			}
			while(memcmp(data + offset, "\r\nAuthorization", 15))
			{
				ssl_end = offset++;
			}
			memcpy(ssl_url,data + ssl_start + 7, ssl_end - ssl_start - 6);
			
			HF_Debug(DEBUG_LEVEL_LOW, "/api/v1 sl_url %s\nssl_end %d\nssl_start %d\n", ssl_url,ssl_end,ssl_start);

			my_ssl_test(ssl_url, data, len); // do SSL Get/Post
			
			offset = 0;
		}
		else
		{
			#if 1
			
			while(memcmp(data + offset, "Host:", 5))
			{
				ssl_start = offset++;
			}
			while(memcmp(data + offset, "\r\nAuthorization", 15))
			{
				ssl_end = offset++;
			}
			while(memcmp(data + offset, "sr=", 3))
			{
				sas_length_sr = offset++;
			}
			while(memcmp(data + offset, "&sig=", 5))
			{
				sas_length_sig = offset;
				secret_start = offset++;
			}
			/*
			while(memcmp(data + offset, "&se=", 4))
			{
				secret_end = offset++;
			}
			*/
			offset = 0;
			
			memcpy(ssl_url,data + ssl_start + 7, ssl_end - ssl_start - 6);
			HF_Debug(DEBUG_LEVEL_LOW, "ssl_url %s\nssl_end %d\nssl_start %d\n", ssl_url,ssl_end,ssl_start);

			memcpy(sas_1, data + sas_length_sr + 4, sas_length_sig - sas_length_sr - 3);
			HF_Debug(DEBUG_LEVEL_LOW, "sas_1 %s sas_length_sr %d sas_length_sig %d\n", sas_1,sas_length_sr,sas_length_sig);

			memcpy(Azure_Key, data + secret_start + 6, 44);
			HF_Debug(DEBUG_LEVEL_LOW, "Azure_Key %s secret_start %d\n", Azure_Key,/*secret_end,*/secret_start);
			
			for(i_k = 0; i_k < len; i_k++)
			{	
				sslsendnum = AddSignature(sslsendbuf,data);
			}

			my_ssl_test(ssl_url, sslsendbuf, sslsendnum); // do SSL Get/Post

			#endif

			#if 0

			for(i_k = 0; i_k < len; i_k++)
			{	
				sslsendnum = AddSignature(sslsendbuf,data);
			}

			my_ssl_test(ssl_url, sslsendbuf, sslsendnum); // do SSL Get/Post

			#endif 
		}

		return 0;
	}
	
	return len;
}

static void show_reset_reason(void)
{
	uint32_t reset_reason=0;
	
	reset_reason = hfsys_get_reset_reason();
	
#if 1
	u_printf("reset_reasion:%08x\n",reset_reason);
#else	
	if(reset_reason&HFSYS_RESET_REASON_ERESET)
	{
		u_printf("ERESET\n");
	}
	if(reset_reason&HFSYS_RESET_REASON_IRESET0)
	{
		u_printf("IRESET0\n");
	}
	if(reset_reason&HFSYS_RESET_REASON_IRESET1)
	{
		u_printf("IRESET1\n");
	}
	if(reset_reason==HFSYS_RESET_REASON_NORMAL)
	{
		u_printf("RESET NORMAL\n");
	}
	if(reset_reason&HFSYS_RESET_REASON_WPS)
	{
		u_printf("RESET FOR WPS\n");
	}
	if(reset_reason&HFSYS_RESET_REASON_SMARTLINK_START)
	{
		u_printf("RESET FOR SMARTLINK START\n");
	}
	if(reset_reason&HFSYS_RESET_REASON_SMARTLINK_OK)
	{
		u_printf("RESET FOR SMARTLINK OK\n");
	}
	if(reset_reason&HFSYS_RESET_REASON_WPS_OK)
	{
		u_printf("RESET FOR WPS OK\n");
	}
#endif
	
	return;
}

void app_init(void)
{
	u_printf("app_init\n");
}

int USER_FUNC app_main (void)
{	
	HF_Debug(DEBUG_LEVEL,"sdk version(%s),the app_main start time is %s %s\n",hfsys_get_sdk_version(),__DATE__,__TIME__);
	if(hfgpio_fmap_check(g_module_id)!=0)
	{
		while(1)
		{
			HF_Debug(DEBUG_ERROR,"gpio map file error\n");
			msleep(1000);
		}
	}
	
	show_reset_reason();
	
	if(hfsmtlk_is_start())
		return 0;

	//this is a new function, can define the stack size for UART thread
	if(hfnet_start_uart_ex(HFTHREAD_PRIORITIES_LOW,(hfnet_callback_t)uart_recv_callback, 2048)!=HF_SUCCESS)
	{
		HF_Debug(DEBUG_WARN,"start uart fail!\n");
	}
	
	while(!hfnet_wifi_is_active())
	{
		msleep(50);
	}
	
	if(hfnet_start_assis(ASSIS_PORT)!=HF_SUCCESS)
	{
		HF_Debug(DEBUG_WARN,"start assis fail\n");
	}

//	hfthread_create((PHFTHREAD_START_ROUTINE)my_ssl_task, "my_ssl_task", 2048, NULL, 3, NULL, NULL);
	
	/*if(hfnet_start_uart(HFTHREAD_PRIORITIES_LOW,(hfnet_callback_t)uart_recv_callback)!=HF_SUCCESS)
	{
		HF_Debug(DEBUG_WARN,"start uart fail!\n");
	}
	if(hfnet_start_socketa(HFTHREAD_PRIORITIES_LOW,(hfnet_callback_t)socketa_recv_callback)!=HF_SUCCESS)
	{
		HF_Debug(DEBUG_WARN,"start socketa fail\n");
	}
	if(hfnet_start_socketb(HFTHREAD_PRIORITIES_LOW,(hfnet_callback_t)socketb_recv_callback)!=HF_SUCCESS)
	{
		HF_Debug(DEBUG_WARN,"start socketb fail\n");
	}*/

	return 1;

}
#endif