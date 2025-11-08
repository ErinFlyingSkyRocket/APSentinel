/* ESP32 Wi-Fi sniffer + secure uploader
   - Sniffs beacons/probe-resp; de-duplicates APs by BSSID
   - Table shows SSID, BSSID, OUI, CH, RSSI (current/best), #beacons, last-seen,
     SECURITY, RSN(Group/Pair), AKM(s), PMF
   - Auto-stop after 30s, then build JSON, SHA-256 + ECDSA P-256 sign per record,
     POST over HTTPS (TLS/ECDHE) to Flask server
   - Retry upload with BOOT button (GPIO0) if it failed

   Use only on networks you own / have permission to test.
*/

#include <WiFi.h>
#include <HTTPClient.h>
#include <WiFiClientSecure.h>
#include <ArduinoJson.h>
#include <Preferences.h>
#include <vector>
#include <algorithm>
// ---- mbedTLS compatibility (2.x vs 3.x) ----
#include "mbedtls/version.h"

struct Row;

#if MBEDTLS_VERSION_NUMBER >= 0x03000000
  // Access private members via MBEDTLS_PRIVATE() in 3.x
  #define ECP_GRP(ctx)   (ctx.MBEDTLS_PRIVATE(grp))
  #define ECP_D(ctx)     (ctx.MBEDTLS_PRIVATE(d))
  #define ECP_Q(ctx)     (ctx.MBEDTLS_PRIVATE(Q))
  #define MPI_X(P)       ((P).MBEDTLS_PRIVATE(X))
  #define MPI_Y(P)       ((P).MBEDTLS_PRIVATE(Y))
  #define MPI_Z(P)       ((P).MBEDTLS_PRIVATE(Z))
  // sha256 function names in 3.x (no _ret)
  #define SHA256_START   mbedtls_sha256_starts
  #define SHA256_UPDATE  mbedtls_sha256_update
  #define SHA256_FINISH  mbedtls_sha256_finish
#else
  // Direct field access in 2.x
  #define ECP_GRP(ctx)   (ctx.grp)
  #define ECP_D(ctx)     (ctx.d)
  #define ECP_Q(ctx)     (ctx.Q)
  #define MPI_X(P)       ((P).X)
  #define MPI_Y(P)       ((P).Y)
  #define MPI_Z(P)       ((P).Z)
  // sha256 function names in 2.x (with _ret)
  #define SHA256_START   mbedtls_sha256_starts_ret
  #define SHA256_UPDATE  mbedtls_sha256_update_ret
  #define SHA256_FINISH  mbedtls_sha256_finish_ret
#endif

extern "C" {
  #include "esp_wifi.h"
  #include "esp_wifi_types.h"
  #include "esp_err.h"
}

// --- WiFi event handler to see disconnect reason ---
void WiFiEvent(WiFiEvent_t event, WiFiEventInfo_t info) {
  if (event == ARDUINO_EVENT_WIFI_STA_DISCONNECTED) {
    Serial.printf("[WiFi] DISCONNECTED. reason = %d\n", info.wifi_sta_disconnected.reason);
  }
}

// ---------- YOUR SETTINGS ----------
#define WIFI_SSID   "YOUR_WIFI_SSID"
#define WIFI_PASS   "YOUR_WIFI_PASSWORD"
// e.g. https://example.com/ingest
#define SERVER_HOST "https://your.server.domain"     // include scheme
#define SERVER_PATH "/api/v1/ingest"                 // your Flask endpoint path
// Root CA PEM that issued your server cert (or self-signed root). Keep it short and correct.
static const char *ROOT_CA_PEM = R"PEM(
-----BEGIN CERTIFICATE-----
...YOUR ROOT/INTERMEDIATE CA HERE...
-----END CERTIFICATE-----
)PEM";
// -----------------------------------


// --- auto-stop after 30s ---
const uint32_t STOP_AFTER_MS = 30 * 1000UL;
uint32_t startMs = 0;
bool sniffStopped = false;
bool sendPending = false;        // set true if we still need to upload
bool uploadDone = false;         // set true once successfully uploaded

// BOOT button (GPIO0) retry
#define BOOT_BTN   0

// ---------- CONFIG ----------
#define FIXED_CH      0      // 1..13; set 0 to enable hopper
#define DWELL_MS      800     // hopper dwell if FIXED_CH == 0
#define MAX_CH        13
#define PRINT_SECS    3       // force a refresh every N seconds even if no new APs
#define MAX_APS       80
#define MIN_RSSI      -95     // filter out very weak beacons
#define SSID_FILTER   ""      // substring to match ("" = no filter)
// ----------------------------

typedef struct {
  uint16_t fc, dur;
  uint8_t  addr1[6], addr2[6], addr3[6];
  uint16_t seq;
} __attribute__((packed)) hdr80211_t;

// --- small helpers ---
String ssidFrom(const uint8_t* p, int len) {
  const int fixed = 12; if (len <= fixed) return "";
  int i = fixed;
  while (i + 2 <= len) {
    uint8_t id = p[i], tl = p[i+1];
    if (i + 2 + tl > len) break;
    if (id == 0) {
      if (tl == 0) return "<hidden>";
      String s; s.reserve(tl);
      for (int k=0;k<tl;k++) s += (char)p[i+2+k];
      return s;
    }
    i += 2 + tl;
  }
  return "";
}

String macToString(const uint8_t m[6]) {
  char buf[18];
  snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X", m[0],m[1],m[2],m[3],m[4],m[5]);
  return String(buf);
}

String ouiFromBSSID(const uint8_t mac[6]) {
  char buf[9];
  snprintf(buf, sizeof(buf), "%02X%02X%02X", mac[0], mac[1], mac[2]);
  return String(buf);
}

// --- Cipher / AKM name mapping ---
String cipherToName(uint8_t o0, uint8_t o1, uint8_t o2, uint8_t type) {
  if (o0==0x00 && o1==0x0F && o2==0xAC) {
    switch (type) {
      case 0:  return "UseGrp";
      case 1:  return "WEP40";
      case 2:  return "TKIP";
      case 4:  return "CCMP";
      case 5:  return "WEP104";
      case 6:  return "GCMP";
      case 8:  return "GCMP256";
      case 9:  return "CCMP256";
      default: break;
    }
  }
  if (o0==0x00 && o1==0x50 && o2==0xF2) {
    if (type==2) return "TKIP";
    if (type==4) return "CCMP";
  }
  char buf[16]; snprintf(buf, sizeof(buf), "%02X-%02X-%02X:%u", o0,o1,o2,type);
  return String(buf);
}

String akmToName(uint8_t o0, uint8_t o1, uint8_t o2, uint8_t type) {
  if (o0==0x00 && o1==0x0F && o2==0xAC) {
    switch (type) {
      case 1:  return "802.1X";
      case 2:  return "PSK";
      case 3:  return "FT-802.1X";
      case 4:  return "FT-PSK";
      case 5:  return "EAP-SHA256";
      case 6:  return "PSK-SHA256";
      case 7:  return "TDLS";
      case 8:  return "SAE";
      case 9:  return "FT-SAE";
      case 11: return "OWE";
      case 12: return "SuiteB-192";
      case 13: return "FT-SuiteB-192";
    }
  }
  if (o0==0x00 && o1==0x50 && o2==0xF2) {
    if (type==1) return "WPA-802.1X";
    if (type==2) return "WPA-PSK";
  }
  char buf[16]; snprintf(buf, sizeof(buf), "%02X-%02X-%02X:%u", o0,o1,o2,type);
  return String(buf);
}

// --- Security parsing ---
struct SecInfo {
  String sec;
  String akms;
  bool   pmfCap=false;
  bool   pmfReq=false;
  bool   hasRSN=false;
  bool   hasWPA=false;
  bool   privacyBit=false;
  uint8_t chFromIE=0;
  uint16_t rsnVersion=0;
  String rsnGroup;
  String rsnPairFirst;
};
// Explicit prototype
SecInfo parseSecurityAndChannel(const uint8_t* pl, int pln);

SecInfo parseSecurityAndChannel(const uint8_t* pl, int pln) {
  SecInfo out;
  if (pln < 12) return out;

  uint16_t capab = pl[10] | (uint16_t(pl[11])<<8);
  out.privacyBit = (capab & 0x0010);

  int i = 12;
  while (i + 2 <= pln) {
    uint8_t id = pl[i], tl = pl[i+1];
    int val = i + 2;
    if (val + tl > pln) break;

    if (id == 3 && tl >= 1) {
      out.chFromIE = pl[val];
    } else if (id == 48 && tl >= 2) {
      out.hasRSN = true;
      int p = val;
      if (p+2 > val+tl) { i = val+tl; continue; }
      out.rsnVersion = pl[p] | (uint16_t(pl[p+1])<<8); p+=2;

      if (p+4 > val+tl) { i = val+tl; continue; }
      out.rsnGroup = cipherToName(pl[p],pl[p+1],pl[p+2],pl[p+3]); p += 4;

      if (p+2 > val+tl) { i = val+tl; continue; }
      { uint16_t pc = pl[p] | (uint16_t(pl[p+1])<<8); p+=2;
        for (uint16_t k=0;k<pc;k++){
          if (p+4 > val+tl) { p = val+tl; break; }
          String name = cipherToName(pl[p],pl[p+1],pl[p+2],pl[p+3]);
          if (k==0) out.rsnPairFirst = name;
          p += 4;
        }
      }

      if (p+2 > val+tl) { i = val+tl; continue; }
      { uint16_t ac = pl[p] | (uint16_t(pl[p+1])<<8); p+=2;
        for (uint16_t k=0;k<ac;k++){
          if (p+4 > val+tl) { p = val+tl; break; }
          String name = akmToName(pl[p],pl[p+1],pl[p+2],pl[p+3]);
          if (out.akms.length()) out.akms += ",";
          out.akms += name;
          p += 4;
        }
      }

      if (p+2 <= val+tl) {
        uint16_t rsnCap = pl[p] | (uint16_t(pl[p+1])<<8);
        out.pmfCap = (rsnCap & (1<<6));
        out.pmfReq = (rsnCap & (1<<7));
      }
    } else if (id == 221 && tl >= 6) {
      const uint8_t *vs = &pl[val];
      if (vs[0]==0x00 && vs[1]==0x50 && vs[2]==0xF2 && vs[3]==0x01) {
        out.hasWPA = true;
        int p = val + 4;
        if (p+2 > val+tl) { i = val+tl; continue; } p += 2;
        if (p+4 > val+tl) { i = val+tl; continue; } p += 4;
        if (p+2 > val+tl) { i = val+tl; continue; }
        uint16_t uc = pl[p] | (uint16_t(pl[p+1])<<8); p += 2;
        if (p + 4*uc > val+tl) { i = val+tl; continue; }
        p += 4*uc;
        if (p+2 > val+tl) { i = val+tl; continue; }
        uint16_t ac = pl[p] | (uint16_t(pl[p+1])<<8); p += 2;
        for (uint16_t k=0;k<ac;k++){
          if (p+4 > val+tl) { p = val+tl; break; }
          String name = akmToName(pl[p],pl[p+1],pl[p+2],pl[p+3]);
          if (out.akms.length()) out.akms += ",";
          out.akms += name;
          p += 4;
        }
      }
    }
    i = val + tl;
  }

  if (out.hasRSN) {
    if (out.akms.indexOf("SAE") >= 0)       out.sec = "WPA3-SAE";
    else if (out.akms.indexOf("OWE") >= 0)  out.sec = "OWE";
    else if (out.akms.length())             out.sec = "WPA2-" + out.akms;
    else                                    out.sec = "WPA2";
  } else if (out.hasWPA) {
    if (out.akms.indexOf("WPA-PSK") >= 0)        out.sec = "WPA-PSK";
    else if (out.akms.indexOf("WPA-802.1X") >= 0) out.sec = "WPA-802.1X";
    else if (out.akms.length())                   out.sec = "WPA-" + out.akms;
    else                                          out.sec = "WPA";
  } else if (out.privacyBit) {
    out.sec = "WEP/Priv";
  } else {
    out.sec = "Open";
  }
  return out;
}

// --- table of seen APs ---
struct Row {
  String ssid;
  String bssid;
  String oui;
  int8_t rssiCur;
  int8_t rssiBest;
  uint8_t ch;
  uint32_t beacons;
  uint32_t lastSeenMs;
  // security
  String sec;
  String rsn;     // RSN column: "Group/Pair" or "-"
  String akm;     // AKM list
  bool pmfCap;
  bool pmfReq;
  bool inUse;
};
Row table[MAX_APS];
volatile bool newData = false;
uint32_t lastPrint = 0;

// country override 1..13
void set_country_1_13() {
  wifi_country_t cc;
  cc.cc[0] = 'S'; cc.cc[1] = 'G'; cc.cc[2] = '\0';
  cc.schan = 1;
  cc.nchan = MAX_CH;
  cc.policy = WIFI_COUNTRY_POLICY_MANUAL;
  esp_wifi_set_country(&cc);
}

// ---------- CRYPTO (mbedTLS) ----------
extern "C" {
  #include "mbedtls/ecdsa.h"
  #include "mbedtls/ecp.h"
  #include "mbedtls/entropy.h"
  #include "mbedtls/ctr_drbg.h"
  #include "mbedtls/sha256.h"
  #include "mbedtls/bignum.h"
}
Preferences prefs;
mbedtls_ecdsa_context ecdsa;
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
bool keyReady = false;

// hex helpers
String toHex(const uint8_t* d, size_t n) {
  static const char* hex="0123456789ABCDEF";
  String s; s.reserve(n*2);
  for (size_t i=0;i<n;i++){ s += hex[d[i]>>4]; s += hex[d[i]&0xF]; }
  return s;
}
bool fromHex(const String& hex, std::vector<uint8_t>& out) {
  if (hex.length()%2) return false;
  out.resize(hex.length()/2);
  for (size_t i=0;i<out.size();i++){
    char c1=hex[2*i], c2=hex[2*i+1];
    auto v=[&](char c)->int{
      if (c>='0'&&c<='9') return c-'0';
      if (c>='A'&&c<='F') return c-'A'+10;
      if (c>='a'&&c<='f') return c-'a'+10;
      return -1;
    };
    int a=v(c1), b=v(c2); if (a<0||b<0) return false;
    out[i] = (a<<4)|b;
  }
  return true;
}

// Load or generate device ECDSA P-256 keypair (stored in NVS as hex big-endian scalars)
bool initKeypair() {
  prefs.begin("ecdsa", false);
  String dHex = prefs.getString("d", "");
  String xHex = prefs.getString("x", "");
  String yHex = prefs.getString("y", "");

  mbedtls_ecdsa_init(&ecdsa);
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  const char *pers = "esp32-ecdsa";
  if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                            (const unsigned char*)pers, strlen(pers)) != 0) {
    Serial.println("[Crypto] DRBG seed failed");
    return false;
  }

  if (dHex.length() && xHex.length() && yHex.length()) {
    // Load existing
    if (mbedtls_ecp_group_load(&ECP_GRP(ecdsa), MBEDTLS_ECP_DP_SECP256R1) != 0) return false;
    if (mbedtls_mpi_read_string(&ECP_D(ecdsa), 16, dHex.c_str()) != 0) return false;
    if (mbedtls_mpi_read_string(&MPI_X(ECP_Q(ecdsa)), 16, xHex.c_str()) != 0) return false;
    if (mbedtls_mpi_read_string(&MPI_Y(ECP_Q(ecdsa)), 16, yHex.c_str()) != 0) return false;
    if (mbedtls_mpi_lset(&MPI_Z(ECP_Q(ecdsa)), 1) != 0) return false;
    keyReady = true;
    return true;
  }

  // Generate new
  if (mbedtls_ecdsa_genkey(&ecdsa, MBEDTLS_ECP_DP_SECP256R1,
                           mbedtls_ctr_drbg_random, &ctr_drbg) != 0) {
    Serial.println("[Crypto] Keygen failed");
    return false;
  }
  // Store as hex strings
  size_t n=0; char* buf=nullptr;
  // d
  mbedtls_mpi_write_string(&ECP_D(ecdsa), 16, nullptr, 0, &n);
  buf = (char*)malloc(n); mbedtls_mpi_write_string(&ECP_D(ecdsa), 16, buf, n, &n);
  dHex = String(buf); free(buf);
  // x
  mbedtls_mpi_write_string(&MPI_X(ECP_Q(ecdsa)), 16, nullptr, 0, &n);
  buf = (char*)malloc(n); mbedtls_mpi_write_string(&MPI_X(ECP_Q(ecdsa)), 16, buf, n, &n);
  xHex = String(buf); free(buf);
  // y
  mbedtls_mpi_write_string(&MPI_Y(ECP_Q(ecdsa)), 16, nullptr, 0, &n);
  buf = (char*)malloc(n); mbedtls_mpi_write_string(&MPI_Y(ECP_Q(ecdsa)), 16, buf, n, &n);
  yHex = String(buf); free(buf);

  // Normalize (uppercase, no spaces)
  dHex.toUpperCase(); xHex.toUpperCase(); yHex.toUpperCase();

  prefs.putString("d", dHex);
  prefs.putString("x", xHex);
  prefs.putString("y", yHex);
  keyReady = true;
  Serial.println("[Crypto] Generated new ECDSA keypair and stored in NVS.");
  return true;
}

// Build canonical string for a row
String canonicalRow(const Row& r) {
  // For deterministic AKM list, sort it
  std::vector<String> parts;
  String akm = r.akm;
  int p=0;
  while (true) {
    int q = akm.indexOf(',', p);
    String token = (q==-1) ? akm.substring(p) : akm.substring(p, q);
    token.trim(); if (token.length()) parts.push_back(token);
    if (q==-1) break; p = q+1;
  }
  std::sort(parts.begin(), parts.end(), [](const String& a, const String& b){ return a.compareTo(b)<0; });
  String akmSorted;
  for (size_t i=0;i<parts.size();i++){ if (i) akmSorted += ","; akmSorted += parts[i]; }

  char pmf[3]; pmf[0] = r.pmfCap?'C':'-'; pmf[1] = r.pmfReq?'R':'-'; pmf[2]=0;

  String s;
  s.reserve(160);
  s += r.bssid; s += "|";
  s += r.ssid; s += "|";
  s += r.oui; s += "|";
  s += String(r.ch); s += "|";
  s += String(r.rssiBest); s += "|";
  s += String(r.beacons); s += "|";
  s += r.sec; s += "|";
  s += r.rsn; s += "|";
  s += akmSorted; s += "|";
  s += pmf; s += "|";
  s += String(r.lastSeenMs);
  return s;
}

// SHA-256
String sha256Hex(const String& s) {
  uint8_t out[32];
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  SHA256_START(&ctx, 0);
  SHA256_UPDATE(&ctx, (const unsigned char*)s.c_str(), s.length());
  SHA256_FINISH(&ctx, out);
  mbedtls_sha256_free(&ctx);
  return toHex(out, 32);
}

// ECDSA sign (hash hex input) -> r,s hex
bool ecdsaSignHashHex(const String& hashHex, String& rHex, String& sHex) {
  if (!keyReady) return false;
  std::vector<uint8_t> h; if (!fromHex(hashHex, h)) return false;
  mbedtls_mpi r, s;
  mbedtls_mpi_init(&r); mbedtls_mpi_init(&s);
  int rc = mbedtls_ecdsa_sign(&ECP_GRP(ecdsa), &r, &s, &ECP_D(ecdsa),
                            h.data(), h.size(),
                            mbedtls_ctr_drbg_random, &ctr_drbg);
  if (rc != 0) { mbedtls_mpi_free(&r); mbedtls_mpi_free(&s); return false; }

  // output hex
  char *buf=nullptr; size_t n=0;
  mbedtls_mpi_write_string(&r, 16, nullptr, 0, &n);
  buf = (char*)malloc(n); mbedtls_mpi_write_string(&r, 16, buf, n, &n);
  rHex = String(buf); free(buf);

  mbedtls_mpi_write_string(&s, 16, nullptr, 0, &n);
  buf = (char*)malloc(n); mbedtls_mpi_write_string(&s, 16, buf, n, &n);
  sHex = String(buf); free(buf);

  rHex.toUpperCase(); sHex.toUpperCase();
  mbedtls_mpi_free(&r); mbedtls_mpi_free(&s);
  return true;
}

// Device identity (public key) for enrollment
String pubXHex() { return prefs.getString("x", ""); }
String pubYHex() { return prefs.getString("y", ""); }

// ---------- SNIFFER CORE ----------
void upsertAP(const String& ssid, const String& bssid, const String& oui,
              int8_t rssi, uint8_t ch, const String& sec, const String& rsn,
              const String& akm, bool pmfCap, bool pmfReq) {
  if (rssi < MIN_RSSI) return;
  if (SSID_FILTER[0] && ssid.indexOf(SSID_FILTER) == -1 && ssid != "<hidden>") return;

  for (int i=0;i<MAX_APS;i++){
    if (table[i].inUse && table[i].bssid == bssid) {
      if (ssid.length()) table[i].ssid = ssid;
      table[i].rssiCur = rssi;
      if (rssi > table[i].rssiBest) table[i].rssiBest = rssi;
      if (ch) table[i].ch = ch;
      table[i].beacons++;
      table[i].lastSeenMs = millis();
      table[i].oui = oui;
      if (sec.length()) table[i].sec = sec;
      table[i].rsn = rsn;
      table[i].akm = akm;
      table[i].pmfCap = pmfCap;
      table[i].pmfReq = pmfReq;
      return;
    }
  }
  for (int i=0;i<MAX_APS;i++){
    if (!table[i].inUse) {
      table[i].inUse = true;
      table[i].ssid = ssid.length()?ssid:"<none>";
      table[i].bssid = bssid;
      table[i].oui = oui;
      table[i].rssiCur = rssi;
      table[i].rssiBest = rssi;
      table[i].ch = ch;
      table[i].beacons = 1;
      table[i].lastSeenMs = millis();
      table[i].sec = sec;
      table[i].rsn = rsn;
      table[i].akm = akm;
      table[i].pmfCap = pmfCap;
      table[i].pmfReq = pmfReq;
      newData = true;
      return;
    }
  }
}

// promiscuous callback
void cb(void* buf, wifi_promiscuous_pkt_type_t) {
  const wifi_promiscuous_pkt_t* p = (wifi_promiscuous_pkt_t*)buf;
  if (!p || p->rx_ctrl.sig_len < (int)sizeof(hdr80211_t)) return;
  const hdr80211_t* h = (const hdr80211_t*)p->payload;

  uint8_t type = h->fc & 0x3;
  uint8_t sub  = (h->fc >> 4) & 0x0F;
  if (type != 0 || !(sub == 8 || sub == 5)) return; // beacons/probe responses

  const uint8_t* pl = p->payload + sizeof(hdr80211_t);
  int pln = p->rx_ctrl.sig_len - sizeof(hdr80211_t);
  if (pln < 0) pln = 0;

  String ssid  = ssidFrom(pl, pln);
  String bssid = macToString(h->addr3);
  String oui   = ouiFromBSSID(h->addr3);

  SecInfo s = parseSecurityAndChannel(pl, pln);
  uint8_t ch = s.chFromIE ? s.chFromIE : p->rx_ctrl.channel;

  String rsnCol = s.hasRSN ? (s.rsnGroup + "/" + (s.rsnPairFirst.length()? s.rsnPairFirst : "-")) : "-";

  upsertAP(ssid, bssid, oui, p->rx_ctrl.rssi, ch, s.sec, rsnCol, s.akms, s.pmfCap, s.pmfReq);
}

// print table
void printTable() {
  int idx[MAX_APS], n=0;
  for (int i=0;i<MAX_APS;i++) if (table[i].inUse) idx[n++] = i;
  for (int a=0;a<n;a++) for (int b=a+1;b<n;b++) {
    if (table[idx[b]].rssiCur > table[idx[a]].rssiCur) { int t=idx[a]; idx[a]=idx[b]; idx[b]=t; }
  }

  Serial.println(F("\nSSID                               BSSID              OUI    CH  RSSI  BEST  #BEAC  LAST(s)  SECURITY       RSN(G/P)    AKM(s)                 PMF"));
  Serial.println(F("-----------------------------------------------------------------------------------------------------------------------------------------------------"));
  uint32_t now = millis();
  for (int k=0;k<n;k++) {
    Row &r = table[idx[k]];
    char pmf[3]; pmf[0] = r.pmfCap?'C':'-'; pmf[1] = r.pmfReq?'R':'-'; pmf[2]=0;
    char line[320];
    snprintf(line, sizeof(line), "%-32s  %-17s  %-6s %2u  %4d  %4d  %5u  %6lu  %-13s  %-10s  %-22s  %s",
             r.ssid.c_str(), r.bssid.c_str(), r.oui.c_str(), r.ch,
             r.rssiCur, r.rssiBest, r.beacons, (unsigned long)((now - r.lastSeenMs)/1000),
             r.sec.c_str(), r.rsn.c_str(), r.akm.c_str(), pmf);
    Serial.println(line);
  }
}

// ---------- JSON BUILD + UPLOAD ----------
String buildJsonPayload() {
  // Count rows
  int n = 0;
  for (int i = 0; i < MAX_APS; i++)
    if (table[i].inUse) n++;

  // Generous capacity for up to MAX_APS rows
  DynamicJsonDocument doc(16384);

  // Device identity (used for enrollment)
  String x   = pubXHex();
  String y   = pubYHex();
  String mac = WiFi.macAddress();

  doc["device"]["type"] = "esp32-sniffer";
  doc["device"]["mac"]  = mac;
  doc["device"]["name"] = mac;          // <-- extra, helps server name it
  doc["device"]["pubkey"]["curve"] = "P-256";
  doc["device"]["pubkey"]["x"]     = x;
  doc["device"]["pubkey"]["y"]     = y;

  doc["meta"]["stopped_after_ms"] = STOP_AFTER_MS;
  doc["meta"]["records"]          = n;

  JsonArray arr = doc.createNestedArray("observations");

  for (int i = 0; i < MAX_APS; i++) {
    if (!table[i].inUse) continue;
    Row &r = table[i];

    // canonical string -> hash
    String canon = canonicalRow(r);
    String h     = sha256Hex(canon);

    // sign the HASH
    String rHex, sHex;
    bool ok = ecdsaSignHashHex(h, rHex, sHex);

    JsonObject o = arr.createNestedObject();
    o["ssid"]         = r.ssid;
    o["bssid"]        = r.bssid;
    o["oui"]          = r.oui;
    o["ch"]           = r.ch;
    o["rssi_best"]    = r.rssiBest;
    o["rssi_cur"]     = r.rssiCur;
    o["beacons"]      = r.beacons;
    o["last_seen_ms"] = r.lastSeenMs;
    o["security"]     = r.sec;
    o["rsn"]          = r.rsn;
    o["akm"]          = r.akm;

    JsonObject pmf = o.createNestedObject("pmf");
    pmf["cap"] = r.pmfCap;
    pmf["req"] = r.pmfReq;

    // send both canonical and hash so server can re-hash if it wants
    o["canonical"]   = canon;
    o["hash_sha256"] = h;

    // signature block
    JsonObject sig = o.createNestedObject("sig");
    sig["alg"] = "ECDSA_P256_SHA256";
    sig["over"] = "SHA256(canonical)";    // <-- tell Django what we signed
    if (ok) {
      sig["r"] = rHex;
      sig["s"] = sHex;
    } else {
      sig["error"] = "sign_failed";
    }
  }

  String out;
  serializeJson(doc, out);
  return out;
}

bool wifiEnsureConnected() {
  // already up?
  if (WiFi.status() == WL_CONNECTED) {
    return true;
  }

  // make 100% sure sniffing is OFF before we try to associate
  esp_wifi_set_promiscuous(false);
  delay(200);  // let driver drain events

  // make the Arduino WiFi behave like your tiny test sketch
  WiFi.persistent(false);          // don't touch flash
  WiFi.setAutoReconnect(false);
  WiFi.setSleep(false);            // keep radio awake

  // go to clean STA
  WiFi.mode(WIFI_STA);
  WiFi.disconnect(true, true);
  delay(200);

  Serial.printf("[WiFi] Connecting to SSID: %s\n", WIFI_SSID);
  WiFi.begin(WIFI_SSID, WIFI_PASS);

  unsigned long t0 = millis();
  const unsigned long timeout = 20000;
  while (WiFi.status() != WL_CONNECTED && (millis() - t0) < timeout) {
    Serial.print(".");
    delay(500);
  }
  Serial.println();

  if (WiFi.status() == WL_CONNECTED) {
    Serial.print("[WiFi] Connected, IP: ");
    Serial.println(WiFi.localIP());
    return true;
  } else {
    Serial.println("[WiFi] Connect failed");
    return false;
  }
}

bool uploadJsonHTTPS(const String& payload) {
  if (!wifiEnsureConnected()) return false;

  bool is_https = String(SERVER_HOST).startsWith("https");
  HTTPClient http;

  String url = String(SERVER_HOST) + String(SERVER_PATH);
  Serial.printf("[HTTP] begin(%s)\n", url.c_str());

  if (is_https) {
    // secure client with root CA
    WiFiClientSecure *client = new WiFiClientSecure();
    client->setCACert(ROOT_CA_PEM);
    if (!http.begin(*client, url)) {
      Serial.println("[HTTP] begin() failed (https)");
      delete client;
      return false;
    }
    http.addHeader("Content-Type", "application/json");
    int code = http.POST((uint8_t*)payload.c_str(), payload.length());
    Serial.printf("[HTTP] POST -> code %d\n", code);
    if (code > 0) {
      String resp = http.getString();
      Serial.printf("[HTTP] Response (%d bytes): %s\n", resp.length(), resp.c_str());
    } else {
      Serial.printf("[HTTP] POST failed: %s\n", http.errorToString(code).c_str());
    }
    http.end();
    delete client;
    return code >= 200 && code < 300;
  } else {
    // plain HTTP
    WiFiClient *client = new WiFiClient();
    if (!http.begin(*client, url)) {
      Serial.println("[HTTP] begin() failed (http)");
      delete client;
      return false;
    }
    http.addHeader("Content-Type", "application/json");
    int code = http.POST((uint8_t*)payload.c_str(), payload.length());
    Serial.printf("[HTTP] POST -> code %d\n", code);
    if (code > 0) {
      String resp = http.getString();
      Serial.printf("[HTTP] Response (%d bytes): %s\n", resp.length(), resp.c_str());
    } else {
      Serial.printf("[HTTP] POST failed: %s\n", http.errorToString(code).c_str());
    }
    http.end();
    delete client;
    return code >= 200 && code < 300;
  }
}

// ---------- SETUP / LOOP ----------
void setup() {
  Serial.begin(115200);
  delay(400);
  pinMode(BOOT_BTN, INPUT_PULLUP);

  // watch disconnect reasons
  WiFi.onEvent(WiFiEvent);

  Serial.println("\nESP32 AP sniffer (dedup table) - with OUI, SECURITY, RSN, AKM, PMF + Secure Upload");

  // crypto keypair
  if (!initKeypair()) {
    Serial.println("[Crypto] Key init failed; will continue without signing.");
  }

  // *** IMPORTANT ***
  // Let Arduino own Wi-Fi from the start
  WiFi.mode(WIFI_STA);
  WiFi.disconnect(true, true);
  delay(200);

  // set country/channels
  set_country_1_13();

  // now just turn on promiscuous on the already-started driver
  esp_wifi_set_promiscuous_rx_cb(&cb);
  wifi_promiscuous_filter_t f{};
  f.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
  esp_wifi_set_promiscuous_filter(&f);
  esp_wifi_set_promiscuous(true);

  if (FIXED_CH) {
    esp_wifi_set_channel(FIXED_CH, WIFI_SECOND_CHAN_NONE);
    Serial.printf("Listening on fixed channel %d\n", FIXED_CH);
  } else {
    Serial.println("Hopper mode 1..13");
  }

  startMs = millis();
}

void tryUploadIfNeeded() {
  // 1) stop sniffing so station mode can connect cleanly
  esp_wifi_set_promiscuous(false);
  delay(120);

  String json = buildJsonPayload();
  Serial.printf("[Upload] Payload size: %u bytes\n", (unsigned)json.length());

  bool ok = uploadJsonHTTPS(json);
  if (ok) {
    Serial.println("[Upload] Success.");
    uploadDone = true;
    sendPending = false;
  } else {
    Serial.println("[Upload] FAILED. Press BOOT to retry.");
    sendPending = true;
  }
}


void loop() {

  // auto-stop after 30s
  if (!sniffStopped && (millis() - startMs) >= STOP_AFTER_MS) {
    esp_wifi_set_promiscuous(false);
    sniffStopped = true;
    printTable();
    Serial.println("\n[Sniffer] Stopped after 30s. Building JSON and uploading...");
    tryUploadIfNeeded();
  }

  // If stopped, allow retry via BOOT button
  if (sniffStopped) {
    if (sendPending && digitalRead(BOOT_BTN) == LOW) {
      delay(15); // debounce
      if (digitalRead(BOOT_BTN) == LOW) {
        Serial.println("[Retry] BOOT pressed. Retrying upload...");
        tryUploadIfNeeded();
        // wait until release
        while (digitalRead(BOOT_BTN) == LOW) delay(10);
      }
    }
    delay(200);
    return;
  }

  // while sniffing
  if (FIXED_CH == 0) {
    for (uint8_t ch=1; ch<=MAX_CH; ch++){
      esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
      uint32_t t0 = millis();
      while (millis() - t0 < DWELL_MS) delay(5);
    }
  } else {
    delay(50);
  }

  if (newData || (millis() - lastPrint) > (PRINT_SECS*1000UL)) {
    newData = false;
    lastPrint = millis();
    printTable();
  }
}