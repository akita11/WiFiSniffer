// definitions.h
#ifndef DEFINITIONS_H
#define DEFINITIONS_H

#include <FastLED.h>

// LEDの色定義
#define LED_SDERROR CRGB(80, 0, 0)
#define LED_NTPERROR CRGB(80, 0, 80)
#define LED_NTP CRGB(0, 80, 0)
#define LED_LOGGING CRGB(0, 0, 80)
#define LED_RECEIVED CRGB(0, 80, 80)
#define LED_NONE CRGB(0, 0, 0)

// ピン定義
#define PIN_BUTTON 0  // 本体ボタンの使用端子（G0）
#define PIN_OUTPUT 43 // 外部LED
#define PIN_LED 21    // 本体フルカラーLEDの使用端子（G21）
#define NUM_LEDS 1    // 本体フルカラーLEDの数

// Wi-Fi定義
#define WIFI_CHANNEL_SWITCH_INTERVAL (500)
#define WIFI_CHANNEL_MAX (14)

// 構造体定義
typedef struct {
    unsigned frame_ctrl : 16;
    unsigned duration_id : 16;
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    unsigned sequence_ctrl : 16;
} wifi_ieee80211_mac_hdr_t;

typedef struct {
    wifi_ieee80211_mac_hdr_t hdr;
    uint8_t payload[0];
} wifi_ieee80211_packet_t;

#endif  // DEFINITIONS_H
