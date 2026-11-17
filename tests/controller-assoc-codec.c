/* Host test for factory-child client attribution.
 *
 * A ZTE child never sends the repository's client sub-TLV 0x70. It answers a STA Metrics Query
 * (0x800d) with a 0x800e / TLV 0x96 <STA MAC, 0x01, BSSID, metrics>, and its AP Capability Report
 * (0x8002) carries the AP Operational BSS TLV (0x83) with the BSSID -> SSID names. The claim under
 * test: one response per client accumulates into <node>.assoc, the SSID comes from the capability
 * report, and a second node's file is untouched.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../src/controller-1905.h"
#include "../src/controller-peer.h"

static unsigned int checks;
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr, "assoc codec failure line %d\n", __LINE__); exit(1); } } while (0)

static const uint8_t controller_mac[6] = {2, 0, 0, 0, 0x19, 0x03};
static const uint8_t child[6] = {0x20, 0x20, 0x51, 0x82, 0x6b, 0xf4};
static const uint8_t child_b[6] = {0xc8, 0x98, 0x28, 0xbd, 0x0e, 0x50};
static const uint8_t bss24[6] = {0x20, 0x20, 0x51, 0x82, 0x6b, 0xf5};
static const uint8_t bss5[6] = {0x20, 0x20, 0x51, 0x82, 0x6b, 0xf6};
static const uint8_t bss_b2[6] = {0xc8, 0x98, 0x28, 0xbd, 0x0e, 0x51};
static const uint8_t phone[6] = {0x3c, 0x5a, 0x37, 0x01, 0x02, 0x03};
static const uint8_t laptop[6] = {0x88, 0xde, 0xa9, 0x11, 0x22, 0x33};

static size_t frame_open(uint8_t *frame, size_t cap, const uint8_t *src, unsigned int type, unsigned int mid)
{
    memset(frame, 0, cap);
    memcpy(frame, controller_mac, 6);
    memcpy(frame + 6, src, 6);
    frame[12] = 0x89;
    frame[13] = 0x3a;
    frame[16] = (uint8_t)(type >> 8);
    frame[17] = (uint8_t)type;
    frame[18] = (uint8_t)(mid >> 8);
    frame[19] = (uint8_t)mid;
    frame[21] = 0x80;
    return CONTROLLER_1905_HEADER;
}

static size_t put_tlv(uint8_t *frame, size_t at, unsigned int type, const uint8_t *value, size_t length)
{
    frame[at] = (uint8_t)type;
    frame[at + 1] = (uint8_t)(length >> 8);
    frame[at + 2] = (uint8_t)length;
    if (value && length)
        memcpy(frame + at + 3, value, length);
    return at + 3 + length;
}

static size_t put_eom(uint8_t *frame, size_t at)
{
    return put_tlv(frame, at, 0, NULL, 0);
}

/* One radio, two BSSes: the shape ap_bss_interfaces() counts and assoc_learn_bss() names. */
static size_t capability_report(uint8_t *frame, size_t cap, const uint8_t *src)
{
    uint8_t tlv[128];
    size_t n = 0, at = frame_open(frame, cap, src, CONTROLLER_MSG_AP_CAPABILITY_REPORT, 1);
    tlv[n++] = 1;
    memcpy(tlv + n, bss24, 6);
    n += 6;
    tlv[n++] = 2;
    memcpy(tlv + n, bss24, 6);
    n += 6;
    tlv[n++] = 3;
    memcpy(tlv + n, "OP2", 3);
    n += 3;
    memcpy(tlv + n, bss5, 6);
    n += 6;
    tlv[n++] = 3;
    memcpy(tlv + n, "OP5", 3);
    n += 3;
    at = put_tlv(frame, at, CONTROLLER_TLV_AP_OPERATIONAL_BSS, tlv, n);
    return put_eom(frame, at);
}

static size_t sta_metrics_response(uint8_t *frame, size_t cap, const uint8_t *src, unsigned int mid,
                                   const uint8_t *sta, const uint8_t *bss)
{
    uint8_t tlv[32];
    size_t n = 0, at = frame_open(frame, cap, src, CONTROLLER_MSG_STA_METRICS_RESPONSE, mid);
    memcpy(tlv + n, sta, 6);
    n += 6;
    tlv[n++] = 0x01;
    memcpy(tlv + n, bss, 6);
    n += 6;
    tlv[n++] = 0x00; /* trailing metric bytes are not read */
    tlv[n++] = 0x00;
    at = put_tlv(frame, at, CONTROLLER_TLV_STA_METRICS, tlv, n);
    return put_eom(frame, at);
}

static void read_assoc(const char *dir, const char *mac, char *out, size_t room)
{
    char path[300];
    FILE *f;
    size_t n = 0;
    out[0] = 0;
    if (snprintf(path, sizeof(path), "%s/%s.assoc", dir, mac) >= (int)sizeof(path))
        return;
    f = fopen(path, "r");
    if (!f)
        return;
    n = fread(out, 1, room - 1, f);
    fclose(f);
    out[n] = 0;
}

int main(void)
{
    uint8_t frame[CONTROLLER_1905_MAX_BYTES];
    char dir[] = "/tmp/zte-assoc-test.XXXXXX";
    char rundir[] = "/tmp/zte-assoc-run.XXXXXX";
    char path[300];
    char text[512];
    FILE *f;
    size_t bytes;

    CHECK(mkdtemp(dir) != NULL);
    CHECK(setenv("ZTE_MESH_PEERS_DIR", dir, 1) == 0);
    CHECK(mkdtemp(rundir) != NULL);
    CHECK(setenv("ZTE_MESH_RUN_DIR", rundir, 1) == 0);
    snprintf(path, sizeof(path), "%s/config", rundir);
    f = fopen(path, "w");
    CHECK(f != NULL);
    fputs("version_mode=128\nradio0.ssid=OP2\nradio1.ssid=OP5\nwifi.dual_band_sync=0\n", f);
    fclose(f);
    snprintf(path, sizeof(path), "%s/state.json", rundir);
    f = fopen(path, "w");
    CHECK(f != NULL);
    fputs("{\"nodes\":[{\"mac\":\"20:20:51:82:6b:f4\",\"bss_detail\":["
          "{\"bssid\":\"20:20:51:82:6b:f5\"},{\"bssid\":\"20:20:51:82:6b:f6\"},"
          "{\"bssid\":\"22:20:51:b2:6b:f6\"}]},"
          "{\"mac\":\"c8:98:28:bd:0e:50\",\"bss_detail\":["
          "{\"bssid\":\"c8:98:28:bd:0e:50\"},{\"bssid\":\"c8:98:28:bd:0e:51\"}]}]}\n", f);
    fclose(f);

    /* The names arrive before any client report. */
    bytes = capability_report(frame, sizeof(frame), child);
    controller_peer_note(frame, bytes);

    bytes = sta_metrics_response(frame, sizeof(frame), child, 2, phone, bss24);
    controller_peer_note(frame, bytes);
    read_assoc(dir, "20:20:51:82:6b:f4", text, sizeof(text));
    CHECK(!strncmp(text, "epoch=", 6));
    CHECK(strstr(text, "3c:5a:37:01:02:03\t20:20:51:82:6b:f5\tOP2\n") != NULL);

    /* A second client on 5G must not erase the first one. */
    bytes = sta_metrics_response(frame, sizeof(frame), child, 3, laptop, bss5);
    controller_peer_note(frame, bytes);
    read_assoc(dir, "20:20:51:82:6b:f4", text, sizeof(text));
    CHECK(strstr(text, "3c:5a:37:01:02:03\t20:20:51:82:6b:f5\tOP2\n") != NULL);
    CHECK(strstr(text, "88:de:a9:11:22:33\t20:20:51:82:6b:f6\tOP5\n") != NULL);

    /* A frame from another node gets its own file; the first node keeps its rows. */
    bytes = capability_report(frame, sizeof(frame), child_b);
    controller_peer_note(frame, bytes);
    bytes = sta_metrics_response(frame, sizeof(frame), child_b, 4, phone, bss24);
    controller_peer_note(frame, bytes);
    read_assoc(dir, "c8:98:28:bd:0e:50", text, sizeof(text));
    CHECK(strstr(text, "3c:5a:37:01:02:03\t20:20:51:82:6b:f5\tOP2\n") != NULL);
    read_assoc(dir, "20:20:51:82:6b:f4", text, sizeof(text));
    CHECK(strstr(text, "88:de:a9:11:22:33\t20:20:51:82:6b:f6\tOP5\n") != NULL);

    /* A truncated 0x96 is not an association. */
    {
        size_t at = frame_open(frame, sizeof(frame), child, CONTROLLER_MSG_STA_METRICS_RESPONSE, 5);
        uint8_t short_value[12];
        memset(short_value, 0, sizeof(short_value));
        memcpy(short_value, phone, 6);
        at = put_tlv(frame, at, CONTROLLER_TLV_STA_METRICS, short_value, sizeof(short_value));
        controller_peer_note(frame, put_eom(frame, at));
    }

    /* The controller's own config + topology name the BSSes even with no 0x8002 report in sight:
     * the second BSS of the second node is the 5 GHz one. */
    bytes = sta_metrics_response(frame, sizeof(frame), child_b, 6, laptop, bss_b2);
    controller_peer_note(frame, bytes);
    read_assoc(dir, "c8:98:28:bd:0e:50", text, sizeof(text));
    CHECK(strstr(text, "88:de:a9:11:22:33\tc8:98:28:bd:0e:51\tOP5\n") != NULL);

    printf("assoc codec ok checks=%u\n--- %s ---\n%s", checks, dir, "");
    read_assoc(dir, "20:20:51:82:6b:f4", text, sizeof(text));
    printf("%s", text);
    return 0;
}
