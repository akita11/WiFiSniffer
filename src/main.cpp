#include <Arduino.h>
#include <M5Unified.h>
#include "esp_wifi.h"
#include "esp_event_loop.h"
#include "nvs_flash.h"
#include "mbedtls/md.h"
#include "SD.h"
#include "time.h"
#include <WiFi.h>

#include "config.h"
// Different versions of the framework have different SNTP header file names and availability.
#if __has_include (<esp_sntp.h>)
 #include <esp_sntp.h>
 #define SNTP_ENABLED 1
#elif __has_include (<sntp.h>)
 #include <sntp.h>
 #define SNTP_ENABLED 1
#endif
#ifndef SNTP_ENABLED
#define SNTP_ENABLED 0
#endif

// ESP32 WiFi Sniffer based on https://lang-ship.com/blog/work/esp32-wifi-sniffer/

//#define DEBUG // serial out, no SD write


char ssid[64];
char ssid_pwd[64];
char ssid_pwd2[64];
bool fOperation = true; // logging at boot
//bool fOperation = false; // no logging at boot
#define NTP_TIMEZONE  "JST-9"


CRGB leds[NUM_LEDS];
File logFile;
bool fSD = false;
uint16_t logNum = 0;
char logFileNamePrefix[32];

void showLED(CRGB c){
  leds[0] = c; FastLED.show();
}


void ShowAlert(CRGB c, uint16_t cycle)
{
  while(1){
    showLED(c); delay(cycle/2);
    showLED(LED_NONE); delay(cycle/2);
  }    
}

#define WLAN_FC_GET_STYPE(fc) (((fc)&0x00f0) >> 4)

uint8_t level = 0, channel = 1;

static wifi_country_t wifi_country = {.cc = "JP", .schan = 1, .nchan = 14}; // Most recent esp32 library struct


static esp_err_t event_handler(void *ctx, system_event_t *event);
static void wifi_sniffer_init(void);
static void wifi_sniffer_set_channel(uint8_t channel);
static const char *wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type);
static void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type);

esp_err_t event_handler(void *ctx, system_event_t *event)
{
  return ESP_OK;
}

uint8_t f = 0;

void wifi_sniffer_init(void)
{
  nvs_flash_init();
  tcpip_adapter_init();
  if (f == 0){
    ESP_ERROR_CHECK(esp_event_loop_init(event_handler, NULL));
    f = 1;
  }
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));
  ESP_ERROR_CHECK(esp_wifi_set_country(&wifi_country)); /* set country for channel range [1, 13] */
  ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
  ESP_ERROR_CHECK(esp_wifi_start());

  wifi_promiscuous_filter_t filter = {.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT};
  ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filter));
  ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
  ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler));
}

void wifi_sniffer_set_channel(uint8_t channel)
{
  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}

const char *wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type)
{
  switch (type)
  {
  case WIFI_PKT_MGMT:
    return "MGMT"; //管理フレーム
  case WIFI_PKT_DATA:
    return "DATA"; //データフレーム
  default:
  case WIFI_PKT_MISC:
    return "MISC"; //その他
  }
}

void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type) {
    // 受信したパケットデータを wifi_promiscuous_pkt_t 型にキャスト
    const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
    
    // ペイロード部分を参照（Wi-Fiフレームデータ全体）
    const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)ppkt->payload;
    
    // MACヘッダ部分を参照（送信元や受信先のアドレスを含む）
    const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;

    // プローブリクエストフレーム（サブタイプ 0x04）以外は処理しない
    if (WLAN_FC_GET_STYPE(hdr->frame_ctrl) != 0x04) {
        return;
    }

    // 現在の日時を取得
    auto dt = M5.Rtc.getDateTime();

    // パケットペイロードの長さから不要な部分を除去（ヘッダー部分を除く）
    uint16_t N = ppkt->rx_ctrl.sig_len - 28;  // 28バイトはMACヘッダーなどの固定部分
    uint8_t buf[N];  // 処理対象のデータを格納するためのバッファ
    uint16_t pb = 0;  // buf のインデックス

    uint16_t p = 0;  // ペイロード全体のインデックス
    while (p < N) {
        uint8_t id = ipkt->payload[p++];  // 要素のIDを取得
        uint8_t len = ipkt->payload[p++];  // 要素の長さを取得

        // 不要なタグをスキップ
        if (id == 0x00 || id == 0x03) {  // 例: SSID (0x00) や DS Parameter Set (0x03)
            p += len;  // 長さ分だけスキップ
        } else {
            buf[pb++] = id;  // IDをバッファに格納
            buf[pb++] = len;  // 長さをバッファに格納
            for (uint8_t i = 0; i < len; i++) {
                buf[pb++] = ipkt->payload[p + i];  // 実際のデータをバッファにコピー
            }
            p += len;  // 次のタグへ
        }
    }

    // SHA-256ハッシュの計算
    byte shaResult[32];
    mbedtls_md_context_t ctx;
    mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 0);
    mbedtls_md_starts(&ctx);
    mbedtls_md_update(&ctx, buf, pb);  // 処理済みデータをハッシュ化
    mbedtls_md_finish(&ctx, shaResult);
    mbedtls_md_free(&ctx);

    // SDカードへログ記録
    char filename[64];
    sprintf(filename, "/log%05d.csv", logNum);
    logFile = SD.open(filename, "a");
    logFile.printf("%02d,%02d,%02d,%02d,%02d,%02d,", dt.date.year % 100, dt.date.month, dt.date.date, dt.time.hours, dt.time.minutes, dt.time.seconds);

    // ハッシュ結果の書き込み
    for (uint8_t i = 0; i < 32; i++) {
        logFile.printf("%02x", shaResult[i]);
    }

    // RSSI値と送信元MACアドレスを記録
    logFile.printf(",%02d,", ppkt->rx_ctrl.rssi);
    logFile.printf("%02x:%02x:%02x:%02x:%02x:%02x,", hdr->addr2[0], hdr->addr2[1], hdr->addr2[2], hdr->addr2[3], hdr->addr2[4], hdr->addr2[5]);

    // フィルタリング後のデータを記録
    for (uint8_t i = 0; i < pb; i++) {
        logFile.printf("%02x", buf[i]);
    }

    logFile.printf("\n");
    logFile.close();
}


void NTPadjust()
{
  // using NTP
  // https://knt60345blog.com/m5stack-ntp/

//  delay(3000);

  if (!SD.exists("/wifi.txt")) ShowAlert(LED_NTPERROR, 1000);

  logFile = SD.open("/wifi.txt", "r");

	uint8_t fin = 0;

	while(fin == 0){
	  uint8_t p = 0, tp = 0;
  	ssid_pwd2[0] = '\0';
  	while(logFile.available() && tp < 3) {
    	char c = (char)logFile.read();
    	if (p > 0 && (c == 0x0d || c == 0x0a)){
      	if (tp == 0) ssid[p] = '\0';
      	else if (tp == 1) ssid_pwd[p] = '\0';
      	else ssid_pwd2[p] = '\0';
      	tp++; p = 0;
    	}
    	if (c != 0x0d && c != 0x0a){
      	if (tp == 0) ssid[p++] = c;
      	else if (tp == 1) ssid_pwd[p++] = c;
      	else ssid_pwd2[p++] = c;
    	}
  	}

	  printf("WiFi settings from wifi.txt: [%s] / [%s] / [%s]\n", ssid, ssid_pwd, ssid_pwd2);

//		WiFi.disconnect(true);  //disconnect form wifi to set new wifi connection
		WiFi.disconnect();
		delay(500);
	  WiFi.mode(WIFI_STA); //init wifi mode
  	if (strlen(ssid_pwd2) > 1){
    	printf("Connecting to %s / %s\n", ssid, ssid_pwd);
      WiFi.begin(ssid, WPA2_AUTH_PEAP, "", ssid_pwd, ssid_pwd2);
    }
  	else{
   	  printf("Connecting to %s\n", ssid);
      WiFi.begin(ssid, ssid_pwd);
    }
  	WiFi.setSleep(false);
  	uint8_t f = 0;
#define N_TRIAL 60 // 30sec
//#define N_TRIAL 10 // 5sec
		uint8_t nTrial = 0;
  	while (WiFi.status() != WL_CONNECTED && nTrial++ < N_TRIAL)
  	{
			M5.update();
			if (M5.BtnA.wasPressed()){
				// press BTN to skip WiFi connection
				for (uint8_t i = 0; i < 5; i++){
					showLED(LED_NTP); delay(100);
					showLED(LED_NONE); delay(100);
				}
				nTrial = N_TRIAL;
			}
    	delay(500);
    	printf(".");
    	if (f == 1) showLED(LED_NTP); else showLED(LED_NONE);
    	f = 1 - f;
  	}
  	showLED(LED_NONE);
		if (nTrial < N_TRIAL) fin = 1;
	}
  logFile.close();

  printf("connected, IP=%s\n", WiFi.localIP().toString().c_str());
  configTzTime(NTP_TIMEZONE, "ntp.nict.jp");

#if SNTP_ENABLED
  while (sntp_get_sync_status() != SNTP_SYNC_STATUS_COMPLETED)
  {
    Serial.print('.');
    delay(1000);
  }
#else
  delay(1600);
  struct tm timeInfo;
  while (!getLocalTime(&timeInfo, 1000))
  {
    Serial.print('.');
  };
#endif
  time_t t = time(nullptr)+1; // Advance one second.
  while (t > time(nullptr));  /// Synchronization in seconds
  M5.Rtc.setDateTime( gmtime( &t ) );
  auto dt = M5.Rtc.getDateTime();
  printf("date&time: %02d%02d%02d %02d%02d%02d\n", dt.date.year % 100, dt.date.month, dt.date.date, dt.time.hours, dt.time.minutes, dt.time.seconds);

  WiFi.disconnect(true);
//  WiFi.mode(WIFI_OFF);

	showLED(LED_NONE);
}

void setup()
{
  auto cfg = M5.config();
  cfg.external_rtc = true; // user external RTC
  M5.begin(cfg);
  Serial.begin(115200);

  FastLED.addLeds<WS2812B, PIN_LED, GRB>(leds, NUM_LEDS); // LED型式、使用端子、LED数を指定（定型文）
  pinMode(PIN_BUTTON, INPUT);                             // 本体ボタン（入力）（INPUT_PULLUPでプルアップ指定）
  pinMode(PIN_OUTPUT, OUTPUT);                            // 外付けLED（出力）

	showLED(LED_NONE);

  // SD on M5Unified
  // https://lang-ship.com/blog/work/m5stack-m5unified-sd/
  // https://qiita.com/MuAuan/items/5fd75695a3c9ad198b1c

  SPI.begin(14, 39, 12);
  fSD = SD.begin(11, SPI, 25000000);
  if (fSD == false) ShowAlert(LED_SDERROR, 200); // SD error = fast RED

  bool fWrite_mac = true;
  uint8_t mac[6];
  char mac_str[32];
  char mac_str_read[32];
  esp_efuse_mac_get_default(mac);
  sprintf(logFileNamePrefix, "%02x%02x%02x%02x%02x%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

  // record mac.txt
  sprintf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  if (SD.exists("/mac.txt")){
    logFile = SD.open("/mac.txt", "r");
    uint8_t p = 0, tp = 0;
    while(logFile.available() && tp == 0) {
      char c = (char)logFile.read();
      if (c == 0x0d || c == 0x0a) tp = 1;
      if (c != 0x0d && c != 0x0a) mac_str_read[p++] = c;
    }
    logFile.close();
    if (strcmp(mac_str, mac_str_read) == 0) fWrite_mac = false;
  }
  if (fWrite_mac){
    printf("writing MAC addres of %s..\n", mac_str);
    logFile = SD.open("/mac.txt", "w");
    logFile.printf("%s\r\n", mac_str);
    logFile.close();
  } 
  M5.Rtc.setSystemTimeFromRtc();

  M5.update();
  if (M5.BtnA.isPressed()){
    NTPadjust();
  }

  // example of 'initial' value: 2000 02 14 12 36 31 
  auto dt = M5.Rtc.getDateTime();
  //dt.date.year = 2000; M5.Rtc.setDateTime(dt); // for debug to initial year value
  printf("year=%d\n", dt.date.year);
  printf("logFilenamePrefix=%s\n", logFileNamePrefix);
  while(dt.date.year < 2023){
    showLED(LED_NTPERROR);delay(100);
    showLED(LED_NONE); delay(100); // NTP error = fast PURPLE
    M5.update();
    if (M5.BtnA.wasPressed()){
      NTPadjust();
      dt = M5.Rtc.getDateTime();
    }
  }
  delay(10);
  wifi_sniffer_init();

  if (fOperation == true)	showLED(LED_LOGGING); else showLED(LED_NONE);

  // https://qiita.com/Kurogara/items/afb092bf7fc7a060c0d8
  //  WiFi.setTxPower(WIFI_POWER_MINUS_1dBm); // set TX power as minimum / no effect in monitor mode (- 80mA)
  
}

void loop()
{
  M5.update();
  if (M5.BtnA.wasDoubleClicked()){
    if (fOperation == true){
      fOperation = false;
      //ESP_ERROR_CHECK(esp_wifi_stop());
      //ESP_ERROR_CHECK(esp_wifi_set_promiscuous(false));
    }
    NTPadjust();
    wifi_sniffer_init();
  }
  else if (M5.BtnA.wasSingleClicked()){
    if (fOperation == true){
      printf("stopped\n");
      fOperation = false;
      //ESP_ERROR_CHECK(esp_wifi_stop());
      //ESP_ERROR_CHECK(esp_wifi_set_promiscuous(false));
			showLED(LED_NONE);
    }
    else{
      fOperation = true;
      logNum++;
      printf("starting log %d\n", logNum);
      //ESP_ERROR_CHECK(esp_wifi_start());
      //ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
    }
  }
  if (fOperation == true){
		showLED(LED_LOGGING); // operating = Blue
    delay(WIFI_CHANNEL_SWITCH_INTERVAL);
    wifi_sniffer_set_channel(channel);
    channel = (channel % WIFI_CHANNEL_MAX) + 1;
  }
}
