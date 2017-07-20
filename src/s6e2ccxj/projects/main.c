/* ========================================
 *
 * Copyright YOUR COMPANY, THE YEAR
 * All Rights Reserved
 * UNPUBLISHED, LICENSED SOFTWARE.
 *
 * CONFIDENTIAL AND PROPRIETARY INFORMATION
 * WHICH IS THE PROPERTY OF your company.
 *
 * ========================================
*/
#include "mcu.h"

#include "emac.h"

// Board dependent settings
static void ConfigureEthernetPins(void) {
  // Configure pin settings to use Ethernet functionality
  FM4_GPIO->PFRC |= 0xF7FF; // MAC0 pins
  FM4_GPIO->PFRD |= 0x0007;

  FM4_GPIO->EPFR14 |= (0x7FF << 18); /// Enable MAC0

  // nRST of PHY: P6A at MCU
  FM4_GPIO->PFR6 &= ~(1u << 0xA); // GPIO, not special function
  FM4_GPIO->DDR6 |= (1u << 0xA);  // Set nRST pin as Output

  // INT02_0, PHY Interrupt signal: PA8 at MCU
  // \todo Implement Ethernet PHY IRQ

  // Ethernet user LED: P6E at MCU
  FM4_GPIO->PFR6 &= ~(1u << 0xE); // GPIO, not special function
  FM4_GPIO->DDR6 |= (1u << 0xE);  // Set Ethernet user LED pin as Output
}

/**
 ******************************************************************************
 ** \brief With this routine you can send an UDP packet without a full-fledged
 **        TCP/IP stack
 **
 ** Here you can write an Ethernet frame into pu8TxBuffer that is sent by MAC
 ** unit with  EMAC_Send() function.
 **
 ** \param  pu8TxBuffer       Buffer containing the complete Ethernet frame
 ** \param  pu8UdpPayload     only the data to be sent
 ** \param  u32PayloadLength  Length of payload data in bytes
 **
 ******************************************************************************/

/******************************************************************************/
/* Global pre-processor symbols/macros ('#define')                            */
/******************************************************************************/
#define MAC0HWADDR0 (0x00)
#define MAC0HWADDR1 (0x01)
#define MAC0HWADDR2 (0x01)
#define MAC0HWADDR3 (0x66)
#define MAC0HWADDR4 (0x73)
#define MAC0HWADDR5 (0x42)

// 00:60:6e:58:00:f9

// 00:04:9f:02:6d:52 mac of my Sabre Board
// Destination HW Address
#define DESTMACADDR0 0x00;
#define DESTMACADDR1 0x04;
#define DESTMACADDR2 0x9F;
#define DESTMACADDR3 0x02;
#define DESTMACADDR4 0x6D;
#define DESTMACADDR5 0x52;

/*
// 18-DB-F2-15-CF-98 mac of my PC
// Destination HW Address
#define DESTMACADDR0 0x18
#define DESTMACADDR1 0xDB;
#define DESTMACADDR2 0xF2;
#define DESTMACADDR3 0x15;
#define DESTMACADDR4 0xCF;
#define DESTMACADDR5 0x98;
*/

/*
//08:00:27:70:af:dd //mac of my virtual box
#define DESTMACADDR0 0x08
#define DESTMACADDR1 0x00;
#define DESTMACADDR2 0x27;
#define DESTMACADDR3 0x70;
#define DESTMACADDR4 0xAF;
#define DESTMACADDR5 0xDD;
*/

// Source IP Address
#define SRCIPADDR0 192;
#define SRCIPADDR1 168;
#define SRCIPADDR2 1;
#define SRCIPADDR3 42;

// Destination IP Address
#define DESTIPADDR0 192;
#define DESTIPADDR1 168;
#define DESTIPADDR2 1;
#define DESTIPADDR3 1;

typedef struct {
  uint8_t dest[6];
  uint8_t src[6];
  uint8_t type;
  uint8_t len;

  uint8_t version_headerLength;
  uint8_t tos;

  uint16_t ipLen;

  uint16_t identification;
  uint16_t fragmentation;

  uint8_t ttl;
  uint8_t protocol;

  uint8_t header_checksumA;
  uint8_t header_checksumB;

  uint32_t ipSrc;
  uint32_t ipDst;

  uint16_t srcPort;
  uint16_t dstPort;

  uint16_t udpLen;
  uint16_t udpCheckSum;
  uint32_t count;
  uint32_t time;
  uint32_t other;
} __attribute__((packed)) udpFrame_t;

void TxBufferUDPFill(uint8_t *pu8TxBuffer, uint8_t *pu8UdpPayload,
                     uint32_t u32PayloadLength) {
  uint32_t u32Index;

  // Ethernet header//////////////////////////////////////////////////
  // Destination Address -- now: broadcast
  pu8TxBuffer[0] = DESTMACADDR0;
  pu8TxBuffer[1] = DESTMACADDR1;
  pu8TxBuffer[2] = DESTMACADDR2;
  pu8TxBuffer[3] = DESTMACADDR3;
  pu8TxBuffer[4] = DESTMACADDR4;
  pu8TxBuffer[5] = DESTMACADDR5;

  // Source Address
  pu8TxBuffer[6] = EMAC0_MAC_ADDRESS0;
  pu8TxBuffer[7] = EMAC0_MAC_ADDRESS1;
  pu8TxBuffer[8] = EMAC0_MAC_ADDRESS2;
  pu8TxBuffer[9] = EMAC0_MAC_ADDRESS3;
  pu8TxBuffer[10] = EMAC0_MAC_ADDRESS4;
  pu8TxBuffer[11] = EMAC0_MAC_ADDRESS5;

  // Type/Length
  pu8TxBuffer[12] = 0x08; // Internet Protocol
  pu8TxBuffer[13] = 0x00;

  // IP header ////////////////////////////////////////////////////////
  pu8TxBuffer[14] = (4 << 4) | 5; // IPv4, Headerlength = 5 32-bit words
  pu8TxBuffer[15] =
      0; // Type of Service - pointless as ignored by any router under the sun
  pu8TxBuffer[16] = (20 + 8 + u32PayloadLength) / 255; // total length high
  pu8TxBuffer[17] = (20 + 8 + u32PayloadLength) % 255; // total length low

  pu8TxBuffer[18] = 0;        // Identification (fragmentation)
  pu8TxBuffer[19] = 0;        // Identification (fragmentation)
  pu8TxBuffer[20] = (1 << 6); // fragmentation: don't fragment bit
  pu8TxBuffer[21] = 0;        // fragment offset

  pu8TxBuffer[22] = 255; // time to live
  pu8TxBuffer[23] = 17;  // protocol: UDP
  pu8TxBuffer[24] =
      0x00; // header checksum, handled by COE (Checksum Offload Engine)
  pu8TxBuffer[25] =
      0x00; // header checksum, handled by COE (Checksum Offload Engine)

  pu8TxBuffer[26] = SRCIPADDR0; // source address
  pu8TxBuffer[27] = SRCIPADDR1;
  pu8TxBuffer[28] = SRCIPADDR2;
  pu8TxBuffer[29] = SRCIPADDR3;

  pu8TxBuffer[30] = DESTIPADDR0; // destination address
  pu8TxBuffer[31] = DESTIPADDR1;
  pu8TxBuffer[32] = DESTIPADDR2;
  pu8TxBuffer[33] = DESTIPADDR3;

  pu8TxBuffer[24] =
      0; // header checksum, handled by COE (Checksum Offload Engine)
  pu8TxBuffer[25] =
      0; // header checksum, handled by COE (Checksum Offload Engine)

  // UDP header ///////////////////////////////////////////////////////
  pu8TxBuffer[34] = 0x22; // source port
  pu8TxBuffer[35] = 0x22;
  pu8TxBuffer[36] = 0x33; // destination port
  pu8TxBuffer[37] = 0x33;

  pu8TxBuffer[38] = 0;                    // UDP length high \todo
  pu8TxBuffer[39] = 8 + u32PayloadLength; // UDP length low \todo
  pu8TxBuffer[40] = 0x00;                 // header checksum \todo
  pu8TxBuffer[41] = 0x00;                 // header checksum \todo

  // Copy payload
  for (u32Index = 0; u32Index < u32PayloadLength; ++u32Index) {
    pu8TxBuffer[42 + u32Index] = pu8UdpPayload[u32Index];
  }
} // TxBufferUDPFill

uint8_t ua8EthBuf[1500];

typedef struct {
  uint32_t count;
  uint32_t time;
  uint32_t other;
} msgPayLoad_t;
msgPayLoad_t msgPayLoad;
#include "gpio/gpio.h"

int main(void) {

  /* Place your initialization/startup code here (e.g. Drv_Init()) */
  stc_emac_config_t stcEmacConfig;
  static uint32_t u32TxFrames = 0;

  // Define Ethernet MAC 0 Configuration
  PDL_ZERO_STRUCT(stcEmacConfig);
  stcEmacConfig.au8MacAddress[0] = EMAC0_MAC_ADDRESS0;
  stcEmacConfig.au8MacAddress[1] = EMAC0_MAC_ADDRESS1;
  stcEmacConfig.au8MacAddress[2] = EMAC0_MAC_ADDRESS2;
  stcEmacConfig.au8MacAddress[3] = EMAC0_MAC_ADDRESS3;
  stcEmacConfig.au8MacAddress[4] = EMAC0_MAC_ADDRESS4;
  stcEmacConfig.au8MacAddress[5] = EMAC0_MAC_ADDRESS5;

  FM4_FLASH_IF->FBFCR = 0x01; /* Trace Buffer enable */

  const uint32_t loadValue = 1000000;

  // Ethernet MAC 0 initialization
  ConfigureEthernetPins();
  Emac_Init(&EMAC0, &stcEmacConfig);
  Emac_Autonegotiate(&EMAC0);
  while (Emac_GetLinkStatus(&EMAC0) != EMAC_LinkStatusLinkUp)
    ;
  SysTick->CTRL = 0;
  SysTick->VAL = 0;
  SysTick->LOAD = loadValue;
  SysTick->CTRL = (SysTick_CTRL_ENABLE_Msk | SysTick_CTRL_CLKSOURCE_Msk);

  Gpio1pin_InitOut(GPIO1PIN_P1A, Gpio1pin_InitVal(1u));
  uint32_t lastTime = 0;
  uint32_t lastOther = 0;
  for (;;) {
    Gpio1pin_InitOut(GPIO1PIN_PB2, Gpio1pin_InitVal(1u));
    Gpio1pin_InitOut(GPIO1PIN_P18, Gpio1pin_InitVal(1u));
    u32TxFrames++;
    msgPayLoad.count = u32TxFrames;
    msgPayLoad.time = lastTime;
    msgPayLoad.other = lastOther;
    lastTime = 0;
    lastOther = 42;
    TxBufferUDPFill(ua8EthBuf, (uint8_t *)&msgPayLoad, sizeof(msgPayLoad));

    en_result_t res;

    udpFrame_t frame;
    frame.dstPort = 0;

    Gpio1pin_InitOut(GPIO1PIN_PB2, Gpio1pin_InitVal(0u)); // green
    do {
      Emac_Autonegotiate(&EMAC0);
      SysTick->VAL = 0;
      SysTick->LOAD = loadValue;
      SysTick->CTRL = 0;

      SysTick->CTRL = (SysTick_CTRL_ENABLE_Msk | SysTick_CTRL_CLKSOURCE_Msk);

      res = Emac_TxFrame(&EMAC0, ua8EthBuf, 42 + sizeof(msgPayLoad));

    } while (res != Ok);
    Gpio1pin_InitOut(GPIO1PIN_PB2, Gpio1pin_InitVal(1u)); // green off

    Gpio1pin_InitOut(GPIO1PIN_P1A, Gpio1pin_InitVal(0u)); // red
    int k = 0;
    do {
      k++;
      uint32_t len;

      len = Emac_RxFrame(&EMAC0, (uint8_t *)&frame);
      if (len != 0 && frame.dstPort == 0x2222) {
        lastTime = loadValue - SysTick->VAL;
        lastOther = frame.count;
        Gpio1pin_InitOut(GPIO1PIN_P18, Gpio1pin_InitVal(0u)); // blue
        break;
      }
    } while (FM_DT->TIMER1VALUE != 0 && k != 0x100000);

    Gpio1pin_InitOut(GPIO1PIN_P1A, Gpio1pin_InitVal(1u)); // red off
    /*



    */
    /* Place your application code here. */
  }
}

/* [] END OF FILE */
